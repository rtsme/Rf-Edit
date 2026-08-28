"""
Codec for the RF Online client's `.edf` OdinTeam container.

BACKLOG #9 found all 32 client `.edf` files sharing one container and could
not read them; BACKLOG #35 recovered the codec from the client's own decoder
rather than from the ciphertext. The transform below is a transcription of
`RF_Online.bin`'s loader -- see `docs/knowledge/edf-container-format.md` in
the umbrella repo for the disassembly evidence and the exact addresses.

Layout, straight off the client's header reader at `FUN_005cb890`
(0x005cb890), which reads the parts in this order:

    offset 0            29 bytes   ASCII magic "RF Online by OdinTeam s(^O^)z"
    offset 29            4 bytes   <u32 LE> payload length
    offset 33            N bytes   encrypted payload
    offset 33 + N      256 bytes   scrambled key -- a TRAILER, at end of file

That is the whole of the 289-byte overhead BACKLOG #9 measured but could not
account for: 29 + 4 + 256 = 289. The client never compares the magic, it just
skips 29 bytes, which is why the string appears nowhere in the binary.

The key is per file, so this is not the single global keystream BACKLOG #9's
two-file comparison suggested -- but it travels inside the file, so one codec
still opens all 32 with no external secret.

Unscrambling the key (`FUN_005cbb00`) is three passes over the 256 bytes:
alternating subtract/add of a power-of-two table, a full reverse, then a swap
of adjacent byte pairs. Decrypting the payload (`FUN_005cba00`) then walks it
byte by byte, subtracting the key byte at even positions and adding it at odd
ones, indexing the key at `(i + 1) % 256`.

Every step is an exact inverse of a corresponding encode step, so a decode
followed by an encode reproduces the original file byte for byte. `--check`
proves that against real files rather than assuming it.

Inside the payload
------------------

BACKLOG #44 read the payload. 17 of the 32 files are a **table chain**: tables
laid end to end, each one an 8-byte `<u32 record_count><u32 record_size>`
header followed by `record_count * record_size` bytes of fixed-width records.
That is the server's `rf_dat.py` container minus its `field_count`, which is
why those tables can be handed straight to `rf_dat.Table` and come out as CSV.

The other 15 open (the container is the container) but do **not** parse as a
chain. Their tables carry only a `<u32 record_count>` header, with the record
layout compiled into the client rather than written in the file, and several
mix in length-prefixed strings, so their records are not even all the same
size. BACKLOG #46 added the second model those need -- a hand-derived
**grammar** per file (`EDF_TABLE_GRAMMARS`), an ordered field list where a
field may be fixed-width or variable-width. Two files have one so far,
`NDLanguage.edf` and `NDStore.edf`.

BACKLOG #52 then found that two of the 13 left over are not a third structure
at all: `en-ph/Exp.edf` and `en-ph/Player.edf` are the server's **plain .dat
container** -- the full 12-byte `<count><field_count><record_size>` header --
sitting inside the `.edf` encryption unchanged. They broke the chain walk only
because it reads eight bytes where they write twelve. That extra `field_count`
is what makes them readable without disassembling anything: `parse_dat_tables`
refuses unless a schema inferred from the record bytes alone comes out with
exactly the number of fields the header declares.

The remaining 11 stay opaque blobs until someone reads the client's reader for
them: `--classify` says which file is which and why, and every parser here
refuses rather than guessing, because a plausible-looking mis-parse would
corrupt the file on write. See `docs/knowledge/edf-payload-tables.md` for the
per-file evidence.

Usage:
    python rf_edf.py <file.edf> ... --check          # decode+re-encode, diff vs original
    python rf_edf.py <file.edf> ... --classify       # chain, grammar, .dat or none, and why
    python rf_edf.py <file.edf> ... --check-tables   # payload -> CSV -> payload, byte-exact
    python rf_edf.py <file.edf> --out payload.bin --key-out key.bin
    python rf_edf.py payload.bin --encode --key key.bin --out file.edf

    from rf_edf import decrypt, encrypt
        payload, key = decrypt(open("Item.edf", "rb").read())
        assert encrypt(payload, key) == open("Item.edf", "rb").read()

    from rf_edf import parse_table_chain, build_table_chain
        tables = parse_table_chain(payload, "Store.edf")
        assert build_table_chain(tables) == payload

    from rf_edf import grammar_for, parse_var_tables, build_var_tables
        tables = parse_var_tables(payload, grammar_for("NDStore.edf"), "NDStore.edf")
        assert build_var_tables(tables) == payload

    from rf_edf import parse_dat_tables, build_dat_tables
        tables = parse_dat_tables(payload, "Player.edf")
        assert build_dat_tables(tables) == payload
"""
import argparse
import csv
import json
import os
import re
import struct
import sys
import tempfile

from rf_dat import (HEADER_SIZE, SchemaError, Table, decode, encode,
                    escape_text, field_size, infer_schema, parse_value,
                    read_schema_json, unescape_text, verify_schema,
                    write_schema_json)

MAGIC = b"RF Online by OdinTeam s(^O^)z"
LENGTH_FORMAT = "<I"
KEY_LENGTH = 256
OVERHEAD = len(MAGIC) + struct.calcsize(LENGTH_FORMAT) + KEY_LENGTH  # 289

# The client builds this table on the stack in FUN_005cbb00 as the literal
# bytes 01 02 04 08 10 20 40 80.
_DIGITS = (1, 2, 4, 8, 16, 32, 64, 128)

# A chain table's header: the server .dat header (count, field_count, size)
# with the middle number left out.
CHAIN_HEADER = "<2I"
CHAIN_HEADER_SIZE = struct.calcsize(CHAIN_HEADER)

# String widths the client's tables actually use: 64-byte names, 32/16-byte
# names (BACKLOG #50), and 4-byte item/quest codes. Tried widest first -- see
# infer_schema.
EDF_STRING_WIDTHS = (64, 32, 16, 4)

# A 16/32-byte slot readily contains one real name among hundreds of
# all-fill records -- "at least one text record" (the old rule) calls it a
# string correctly, but most of its values are still fill and read as junk.
# Measured over the 17 chain files (BACKLOG #50): the worst offender
# (Quest.edf's item-name slot) has real text in 22.6% of its records, so
# anything below that share still lets it through; 0.3 clears it with margin
# and is a plateau -- 0.25 through 0.45 all land on materially the same slot
# set. Below it, junk share is non-monotonic in the threshold (excluding the
# worst slots first can raise the *average* among what's left before the
# threshold finally clears them), so this is not a value to nudge without
# re-running the measurement. See docs/knowledge/edf-payload-tables.md.
EDF_MIN_TEXT_SHARE = 0.3

# Guard rails for the chain walk. A real table's record is a handful of bytes
# to a couple of kilobytes; anything past these is a misread header, and
# saying so beats allocating on a garbage length.
MAX_RECORD_SIZE = 1 << 16
MAX_RECORD_COUNT = 1 << 24


class EdfError(SchemaError):
    """Raised when a file is not a well-formed OdinTeam container.

    Subclasses `rf_dat.SchemaError` so one `except SchemaError` catches both a
    bad container and a table inside it that will not lay out.
    """


def _require_key(key):
    key = bytes(key)
    if len(key) != KEY_LENGTH:
        raise EdfError("EDF key must be exactly %d bytes, got %d" % (KEY_LENGTH, len(key)))
    return key


def decode_key(scrambled):
    """Undo the key scrambling -- the client's FUN_005cbb00, in order."""
    key = bytearray(_require_key(scrambled))
    for i in range(KEY_LENGTH):
        digit = _DIGITS[(i + 1) % len(_DIGITS)]
        key[i] = ((key[i] - digit) if i % 2 == 0 else (key[i] + digit)) & 0xFF
    key.reverse()
    for i in range(0, KEY_LENGTH, 2):
        key[i], key[i + 1] = key[i + 1], key[i]
    return bytes(key)


def encode_key(key):
    """Exact inverse of `decode_key` -- the same three passes, run backwards.

    The reverse and the pair swap are involutions, so only the arithmetic pass
    flips sign; running the three in the opposite order is what makes this an
    inverse rather than a second application.
    """
    key = bytearray(_require_key(key))
    for i in range(0, KEY_LENGTH, 2):
        key[i], key[i + 1] = key[i + 1], key[i]
    key.reverse()
    for i in range(KEY_LENGTH):
        digit = _DIGITS[(i + 1) % len(_DIGITS)]
        key[i] = ((key[i] + digit) if i % 2 == 0 else (key[i] - digit)) & 0xFF
    return bytes(key)


def _transform(payload, key, decoding):
    """The client's FUN_005cba00 payload walk, and its inverse.

    Decoding subtracts the key byte at even positions and adds it at odd ones;
    encoding does the opposite. The key index is `(i + 1) % 256`, not `i`.
    """
    out = bytearray(payload)
    for i in range(len(out)):
        k = key[(i + 1) % KEY_LENGTH]
        if (i % 2 == 0) == decoding:
            out[i] = (out[i] - k) & 0xFF
        else:
            out[i] = (out[i] + k) & 0xFF
    return bytes(out)


def decrypt(blob):
    """Return `(payload, key)` for the bytes of a `.edf` file.

    `key` comes back unscrambled, ready to hand straight to `encrypt`.
    """
    if len(blob) < OVERHEAD:
        raise EdfError("file is %d bytes, too small for the %d-byte container overhead"
                       % (len(blob), OVERHEAD))
    if blob[:len(MAGIC)] != MAGIC:
        raise EdfError("not an OdinTeam RF Online container (magic does not match)")

    payload_length = struct.unpack_from(LENGTH_FORMAT, blob, len(MAGIC))[0]
    expected = payload_length + OVERHEAD
    if len(blob) != expected:
        raise EdfError("header declares a %d-byte payload, so the file should be %d bytes, but it is %d"
                       % (payload_length, expected, len(blob)))

    start = len(MAGIC) + struct.calcsize(LENGTH_FORMAT)
    key = decode_key(blob[-KEY_LENGTH:])
    return _transform(blob[start:start + payload_length], key, decoding=True), key


def encrypt(payload, key):
    """Rebuild a `.edf` file from a decoded payload and its decoded key."""
    key = _require_key(key)
    if len(payload) > 0xFFFFFFFF:
        raise EdfError("payload is too large for the container's 32-bit length field")
    return (MAGIC
            + struct.pack(LENGTH_FORMAT, len(payload))
            + _transform(payload, key, decoding=False)
            + encode_key(key))


def decrypt_file(path):
    with open(path, "rb") as f:
        return decrypt(f.read())


# --------------------------------------------------------------------------
# the payload: a chain of tables
# --------------------------------------------------------------------------

def chain_layout(payload, source="EDF payload"):
    """Return `[(record_count, record_size), ...]` for a table-chain payload.

    Structure only -- no schema inference, no row decoding -- so this is cheap
    enough to run over every file just to ask whether it *is* a chain.

    Raises `EdfError` naming the first table that does not fit. The test is
    strict on purpose: the chain has to consume the payload to the last byte,
    because a chain that ends early is a chain that was read wrong.
    """
    layout = []
    offset = 0
    while offset < len(payload):
        remaining = len(payload) - offset
        if remaining < CHAIN_HEADER_SIZE:
            raise EdfError(
                "%s: %d byte(s) left after table %d -- too few for another "
                "8-byte table header" % (source, remaining, len(layout)))
        count, rec_size = struct.unpack_from(CHAIN_HEADER, payload, offset)
        if rec_size == 0 or rec_size > MAX_RECORD_SIZE or count > MAX_RECORD_COUNT:
            raise EdfError(
                "%s: table %d at offset %d reads as %d records of %d bytes, "
                "which is not a table header"
                % (source, len(layout), offset, count, rec_size))
        end = offset + CHAIN_HEADER_SIZE + count * rec_size
        if end > len(payload):
            raise EdfError(
                "%s: table %d at offset %d claims %d records of %d bytes, "
                "%d past the end of the payload"
                % (source, len(layout), offset, count, rec_size,
                   end - len(payload)))
        layout.append((count, rec_size))
        offset = end
    if not layout:
        raise EdfError("%s: payload is empty" % source)
    return layout


def _table_from_records(data, count, rec_size, source):
    """One chain table as an `rf_dat.Table`, schema inferred from the bytes.

    There is no reference schema for any client table and no field count in
    the header, so the schema is inferred and the field count is whatever the
    inference produced -- hence `strict_field_count=False`, the same relaxation
    the server's per-map tables already use.
    """
    if count == 0:
        # Nothing to infer from. Numbers are the safe reading: a string column
        # would be a claim about bytes that are not there.
        if rec_size % 4:
            raise EdfError(
                "%s is empty and its %d-byte record is not a whole number of "
                "dwords, so there is no evidence for any layout"
                % (source, rec_size))
        schema = [("Val%d" % (i + 1), "dword") for i in range(rec_size // 4)]
        schema_source = "placeholder (table is empty)"
    else:
        records = [data[i * rec_size:(i + 1) * rec_size] for i in range(count)]
        schema = infer_schema(records, rec_size,
                              string_widths=EDF_STRING_WIDTHS,
                              allow_short_numbers=True,
                              min_text_share=EDF_MIN_TEXT_SHARE)
        schema_source = "inferred from records"
    verify_schema(schema, len(schema), rec_size)

    rows = []
    pos = 0
    for _ in range(count):
        row = {}
        for name, ftype in schema:
            width = field_size(ftype)
            row[name] = decode(data[pos:pos + width], ftype)
            pos += width
        rows.append(row)
    return Table(schema, rows, len(schema), rec_size, source=source,
                 schema_source=schema_source, strict_field_count=False)


def parse_table_chain(payload, source="EDF payload"):
    """Parse a table-chain payload into `rf_dat.Table`s, consuming every byte.

    Raises `EdfError` when the payload is not a clean chain, so a caller can
    keep it as an opaque blob. Guessing at a structure that only mostly fits
    would produce CSVs that rebuild to different bytes -- a corrupted file that
    looks edited rather than one that looks unreadable.
    """
    tables = []
    offset = 0
    for count, rec_size in chain_layout(payload, source):
        start = offset + CHAIN_HEADER_SIZE
        end = start + count * rec_size
        tables.append(_table_from_records(
            payload[start:end], count, rec_size,
            "%s#%d" % (source, len(tables))))
        offset = end
    return tables


def build_table_chain(tables):
    """Rebuild a table-chain payload from `rf_dat.Table`s.

    `Table.to_bytes` writes the server's 12-byte header, of which a chain
    table keeps the first and third numbers; the middle `field_count` is
    dropped and the record bytes follow unchanged.
    """
    out = bytearray()
    for table in tables:
        body = table.to_bytes()[HEADER_SIZE:]
        out += struct.pack(CHAIN_HEADER, len(table.rows), table.rec_size)
        out += body
    return bytes(out)


def classify(payload, source="EDF payload"):
    """`(layout, reason)` -- the chain layout, or None and why it is not one."""
    try:
        return chain_layout(payload, source), ""
    except EdfError as exc:
        return None, str(exc)

# --------------------------------------------------------------------------
# the third payload: a plain server-style .dat container
# --------------------------------------------------------------------------
#
# BACKLOG #52. Two of the files the chain walk rejected are not a third
# structure at all -- they are the server's own `.dat` container, sitting
# inside the `.edf` encryption unchanged:
#
#     <u32 record_count> <u32 field_count> <u32 record_size>   12-byte header
#     record_count * record_size bytes                         fixed records
#
# That is the chain header *with* the `field_count` a chain table drops, which
# is exactly why they broke the chain walk: read eight bytes where the file
# writes twelve and the record size is really the field count, so the first
# table runs to the wrong place and everything after it is garbage.
# `en-ph/Exp.edf` read as "51 records of 5 bytes" and stopped at offset 263;
# `en-ph/Player.edf` as "5 records of 12 bytes" and stopped at 68.
#
# **The field count is what makes this a derivation rather than a guess.** A
# chain table has nothing in the file to check an inferred schema against
# (hence `strict_field_count=False` over there). Here the header carries a
# second, redundant number, and `parse_dat_tables` refuses unless a schema
# inferred from the record bytes alone -- which never looks at the header --
# comes out with exactly that many fields. Both files clear it: Exp.edf's
# 260-byte record infers as 5 fields against a declared 5, Player.edf's
# 168-byte record as 12 against a declared 12. Two numbers derived
# independently agreeing is the same class of cross-check as NDStore.edf's
# 278 records matching Store.edf's.
#
# Neither of the other 30 payloads closes under this walk, and neither of
# these two closes under the chain walk or has a grammar, so the three
# readings do not compete for a file. See docs/knowledge/edf-payload-tables.md.

DAT_HEADER = "<3I"
DAT_HEADER_SIZE = struct.calcsize(DAT_HEADER)
assert DAT_HEADER_SIZE == HEADER_SIZE


def dat_layout(payload, source="EDF payload"):
    """Return `[(record_count, field_count, record_size), ...]` for a .dat payload.

    Structure only, like `chain_layout`, and strict for the same reason: the
    walk has to consume the payload to the last byte, because a walk that ends
    early read a header at the wrong offset.
    """
    layout = []
    offset = 0
    while offset < len(payload):
        remaining = len(payload) - offset
        if remaining < DAT_HEADER_SIZE:
            raise EdfError(
                "%s: %d byte(s) left after table %d -- too few for another "
                "12-byte table header" % (source, remaining, len(layout)))
        count, field_count, rec_size = struct.unpack_from(
            DAT_HEADER, payload, offset)
        # A field is at least one byte, so more fields than bytes is not a
        # header -- it is a chain header being read twelve bytes wide.
        if (rec_size == 0 or rec_size > MAX_RECORD_SIZE
                or count > MAX_RECORD_COUNT
                or field_count == 0 or field_count > rec_size):
            raise EdfError(
                "%s: table %d at offset %d reads as %d records of %d field(s) "
                "in %d bytes, which is not a table header"
                % (source, len(layout), offset, count, field_count, rec_size))
        end = offset + DAT_HEADER_SIZE + count * rec_size
        if end > len(payload):
            raise EdfError(
                "%s: table %d at offset %d claims %d records of %d bytes, "
                "%d past the end of the payload"
                % (source, len(layout), offset, count, rec_size,
                   end - len(payload)))
        layout.append((count, field_count, rec_size))
        offset = end
    if not layout:
        raise EdfError("%s: payload is empty" % source)
    return layout


def _dat_table_from_records(data, count, field_count, rec_size, source):
    """One .dat table, with the header's field count used as the cross-check.

    Unlike a chain table, this one is checkable: the header says how many
    fields the record has, and `infer_schema` works the layout out from the
    bytes without ever seeing that number. If the two disagree, the reading is
    wrong somewhere and saying so is the only honest answer -- a schema that
    merely adds up to `rec_size` would still write back corrupted records.
    """
    if count == 0:
        raise EdfError(
            "%s is empty, so there are no records to check its declared %d "
            "field(s) against -- the field count is the only thing that makes "
            "this format readable, and an empty table cannot supply it"
            % (source, field_count))
    records = [data[i * rec_size:(i + 1) * rec_size] for i in range(count)]
    schema = infer_schema(records, rec_size,
                          string_widths=EDF_STRING_WIDTHS,
                          allow_short_numbers=True,
                          min_text_share=EDF_MIN_TEXT_SHARE)
    if len(schema) != field_count:
        raise EdfError(
            "%s: the header declares %d field(s) but the record bytes lay out "
            "as %d (%s) -- the two have to agree before this can be read"
            % (source, field_count, len(schema),
               ", ".join(t for _n, t in schema[:8])))
    verify_schema(schema, field_count, rec_size)

    rows = []
    pos = 0
    for _ in range(count):
        row = {}
        for name, ftype in schema:
            width = field_size(ftype)
            row[name] = decode(data[pos:pos + width], ftype)
            pos += width
        rows.append(row)
    return Table(schema, rows, field_count, rec_size, source=source,
                 schema_source="inferred from records (field count checked "
                               "against the header)")


def parse_dat_tables(payload, source="EDF payload"):
    """Parse a .dat-container payload into `rf_dat.Table`s, consuming every byte."""
    tables = []
    offset = 0
    for count, field_count, rec_size in dat_layout(payload, source):
        start = offset + DAT_HEADER_SIZE
        end = start + count * rec_size
        tables.append(_dat_table_from_records(
            payload[start:end], count, field_count, rec_size,
            "%s#%d" % (source, len(tables))))
        offset = end
    return tables


def build_dat_tables(tables):
    """Rebuild a .dat-container payload from `rf_dat.Table`s.

    Nothing to strip here, unlike `build_table_chain`: `Table.to_bytes` writes
    the 12-byte header this format already has.
    """
    out = bytearray()
    for table in tables:
        out += table.to_bytes()
    return bytes(out)

# --------------------------------------------------------------------------
# the other payload: count-only tables with variable-length records
# --------------------------------------------------------------------------
#
# 15 of the 32 files are not chains. Their tables carry a `<u32 record_count>`
# and nothing else: the record layout is compiled into the client. Several
# also carry length-prefixed strings, so records are not even the same size as
# each other -- which is why `rf_dat`'s schema model does not reach them. It
# describes a fixed-size record, and `record_size(schema)` is load-bearing all
# the way down to `Table.to_bytes`.
#
# The model here is a **grammar** rather than a schema: an ordered field list
# that every record in the table follows, where a field may be fixed-width or
# variable-width. The field *list* is uniform even when the record *size* is
# not, so one CSV column per field still works, and the CSV keeps the property
# that matters -- one row per record, columns in record order.
#
# A grammar cannot be inferred. It is hand-derived per file from the payload
# (and, where that is not enough, from the client's reader) and lives in
# `EDF_TABLE_GRAMMARS` below. A file with no entry there stays an opaque blob:
# guessing a layout that happens to consume every byte still writes back
# corrupted records. See docs/knowledge/edf-payload-tables.md.

COUNT_HEADER = "<I"
COUNT_HEADER_SIZE = struct.calcsize(COUNT_HEADER)

# `<u32 len><len bytes>`, the bytes being text with a trailing NUL inside the
# count. The CSV holds the text without that terminator, and `write_field`
# puts it back -- so the length is *derived*, never edited, and a row can be
# retyped freely without anyone having to keep a byte count in step.
#
# Because the length is derived, the terminator is part of the contract rather
# than an observation: `read_field` refuses a blob that is not exactly one
# NUL-terminated string. A blob without one would encode back a byte longer,
# and one with an interior NUL would come back short -- both silent
# corruption. Refusing says the grammar is wrong for that file, which is the
# true statement.
LPSTR = "lpstrz"

# A fixed N-byte NUL-padded field, kept apart from rf_dat's `string[N]`
# deliberately. `string[N]` decodes to the first NUL and re-encodes NUL-padded,
# which is right for the server's `.dat` fields and wrong here: NDStore record
# 18's second name is `COIN EXCHANGE`, NULs, and then twenty bytes of
# uninitialised stack the client never reads. `string[64]` would drop those on
# the floor and the payload would not rebuild. `zstr[N]` treats only the
# *trailing* NUL run as padding, so any N bytes survive the round trip, and a
# field that is clean still reads as clean text in the CSV.
_ZSTR_RE = re.compile(r"^zstr\[(\d+)\]$", re.IGNORECASE)


def field_width(ftype):
    """Bytes this field occupies, or None when that depends on its value."""
    m = _ZSTR_RE.match(ftype)
    if m:
        return int(m.group(1))
    if ftype == LPSTR:
        return None
    return field_size(ftype)


def read_field(data, pos, ftype, where):
    """Decode one field at `pos`, returning `(value, next position)`."""
    m = _ZSTR_RE.match(ftype)
    if m:
        width = int(m.group(1))
        if pos + width > len(data):
            raise EdfError("%s: %d-byte field runs %d byte(s) past the end of "
                           "the table"
                           % (where, width, pos + width - len(data)))
        return data[pos:pos + width].rstrip(b"\x00").decode("latin-1"), pos + width
    if ftype == LPSTR:
        if pos + 4 > len(data):
            raise EdfError("%s: no room for the 4-byte length prefix" % where)
        length = struct.unpack_from("<I", data, pos)[0]
        pos += 4
        if pos + length > len(data):
            raise EdfError("%s: length prefix says %d bytes, %d past the end "
                           "of the table"
                           % (where, length, pos + length - len(data)))
        blob = data[pos:pos + length]
        if not blob.endswith(b"\x00") or b"\x00" in blob[:-1]:
            raise EdfError(
                "%s: the %d-byte string is not one NUL-terminated run (%r) -- "
                "the grammar does not fit this file"
                % (where, length, blob[:32]))
        return blob[:-1].decode("latin-1"), pos + length
    width = field_size(ftype)
    if pos + width > len(data):
        raise EdfError("%s: %s runs %d byte(s) past the end of the table"
                       % (where, ftype, pos + width - len(data)))
    return decode(data[pos:pos + width], ftype), pos + width


def write_field(value, ftype):
    """Encode one field. Exact inverse of `read_field` for anything it read."""
    m = _ZSTR_RE.match(ftype)
    if m:
        width = int(m.group(1))
        raw = str(value).encode("latin-1")
        if len(raw) > width:
            raise ValueError("too long: %d bytes, field holds %d"
                             % (len(raw), width))
        return raw + b"\x00" * (width - len(raw))
    if ftype == LPSTR:
        raw = str(value).encode("latin-1")
        if b"\x00" in raw:
            raise ValueError("must not contain a NUL byte -- the terminator "
                             "is written for you")
        return struct.pack("<I", len(raw) + 1) + raw + b"\x00"
    return encode(value, ftype)


def parse_field(text, ftype):
    """Turn CSV text into a value `write_field` will accept, or raise."""
    m = _ZSTR_RE.match(ftype)
    if m or ftype == LPSTR:
        try:
            raw = text.encode("latin-1")
        except UnicodeEncodeError:
            raise ValueError("contains characters this file's encoding can't "
                             "store (latin-1 only; paste plain text)")
        if m and len(raw) > int(m.group(1)):
            raise ValueError("too long: %d bytes, field holds %s"
                             % (len(raw), m.group(1)))
        if ftype == LPSTR and b"\x00" in raw:
            raise ValueError("must not contain a NUL byte -- the terminator "
                             "is written for you")
        return text
    return parse_value(text, ftype)


def verify_grammar(grammar, source="grammar"):
    """Reject a grammar that could not produce a usable CSV. Returns it."""
    if not grammar:
        raise EdfError("%s: a grammar needs at least one field" % source)
    names = [n for n, _ in grammar]
    if len(set(names)) != len(names):
        dupes = sorted({n for n in names if names.count(n) > 1})
        raise EdfError("%s: duplicate field name(s) %s -- CSV columns must be "
                       "distinct" % (source, ", ".join(dupes)))
    for _name, ftype in grammar:
        field_width(ftype)      # raises SchemaError on an unknown type
    return grammar


# Hand-derived grammars, keyed by lowercase file name. Everything absent here
# is still unhandled and still reported as such -- see the per-file blocker
# table in docs/knowledge/edf-payload-tables.md. Each value is the list of
# tables in the payload, in order, one grammar each.
EDF_TABLE_GRAMMARS = {
    # <u32 6360> then 6360 x (<u32 id><u32 len><len bytes>). Ids run 0..6359
    # in order; every string is NUL-terminated inside its length.
    "ndlanguage.edf": [
        [("Id", "dword"), ("Text", LPSTR)],
    ],
    # <u32 278> then 278 x (<u32 id><64-byte name><64-byte name><u32 len>
    # <len bytes>). The 278 matches Store.edf's single table, which is the
    # cross-check that the reading is right. The two names are identical in
    # 272 of the 278 records and their separate roles are not known, so they
    # are numbered rather than guessed at.
    "ndstore.edf": [
        [("Id", "dword"), ("Name1", "zstr[64]"), ("Name2", "zstr[64]"),
         ("Text", LPSTR)],
    ],
}


def grammar_for(source):
    """The table grammars for a file name, or None if it has none."""
    return EDF_TABLE_GRAMMARS.get(os.path.basename(source).lower())


class VarTable(object):
    """One count-only table: a grammar, and one row per record.

    Deliberately not an `rf_dat.Table` subclass. Everything Table does is
    anchored on a fixed `rec_size` -- the header it writes, the layout it
    verifies, the field count it checks -- and none of that is true here.
    Sharing the class would mean teaching those checks to be optional, on the
    settled path all 17 chain files depend on.
    """

    def __init__(self, grammar, rows, source=None, grammar_source=None):
        self.grammar = verify_grammar(grammar, source or "grammar")
        self.rows = rows
        self.source = source
        self.grammar_source = grammar_source

    @classmethod
    def parse(cls, data, offset, grammar, source):
        """Read `<u32 count>` and its records at `offset`.

        Returns the table and the offset just past it.
        """
        verify_grammar(grammar, source)
        if offset + COUNT_HEADER_SIZE > len(data):
            raise EdfError("%s: %d byte(s) left, too few for a 4-byte record "
                           "count" % (source, len(data) - offset))
        count = struct.unpack_from(COUNT_HEADER, data, offset)[0]
        pos = offset + COUNT_HEADER_SIZE
        if count > MAX_RECORD_COUNT:
            raise EdfError("%s: reads as %d records, which is not a record "
                           "count" % (source, count))
        rows = []
        for i in range(count):
            row = {}
            for name, ftype in grammar:
                row[name], pos = read_field(
                    data, pos, ftype,
                    "%s record %d field %s" % (source, i, name))
            rows.append(row)
        return cls(grammar, rows, source=source,
                   grammar_source="hand-derived (EDF_TABLE_GRAMMARS)"), pos

    def to_bytes(self):
        out = bytearray(struct.pack(COUNT_HEADER, len(self.rows)))
        for i, row in enumerate(self.rows):
            for name, ftype in self.grammar:
                try:
                    out += write_field(row[name], ftype)
                except ValueError as exc:
                    raise EdfError("%s record %d field %s: %s"
                                   % (self.source or "table", i, name, exc))
        return bytes(out)

    @classmethod
    def from_csv(cls, csv_path, grammar):
        t = cls(grammar, [], source=os.path.basename(csv_path),
                grammar_source=os.path.basename(csv_path))
        t.import_csv(csv_path)
        return t

    def export_csv(self, path):
        """One line per record, ASCII-only, LF endings -- as rf_dat.Table."""
        names = [n for n, _ in self.grammar]
        with open(path, "w", newline="", encoding="ascii") as f:
            w = csv.writer(f, lineterminator="\n")
            w.writerow(names)
            for row in self.rows:
                w.writerow([escape_text(str(row[n])) for n in names])

    def import_csv(self, path):
        where = os.path.basename(path)
        with open(path, "r", newline="", encoding="ascii") as f:
            reader = csv.reader(f)
            try:
                header = next(reader)
            except StopIteration:
                raise ValueError("%s is empty" % where)
            expected = [n for n, _ in self.grammar]
            if header != expected:
                raise ValueError(
                    "%s: columns don't match the grammar.\nexpected %d columns "
                    "starting %s\ngot %d columns starting %s\nColumns must not "
                    "be added, removed or reordered -- they are the record "
                    "layout." % (where, len(expected), expected[:4],
                                 len(header), header[:4]))
            rows = []
            for i, rec in enumerate(reader):
                if len(rec) != len(expected):
                    raise ValueError("%s line %d: has %d values, expected %d"
                                     % (where, i + 2, len(rec), len(expected)))
                row = {}
                for (name, ftype), text in zip(self.grammar, rec):
                    try:
                        row[name] = parse_field(unescape_text(text), ftype)
                    except ValueError as exc:
                        raise ValueError("%s line %d, column %s: %s"
                                         % (where, i + 2, name, exc))
                rows.append(row)
        self.rows = rows
        return rows


def parse_var_tables(payload, grammars, source="EDF payload"):
    """Parse a count-only payload into `VarTable`s, consuming every byte.

    The closure test is the chain's: the walk has to land exactly on the last
    byte. A grammar that stops early has read a count or a length at the wrong
    offset, and everything after it is wrong too.
    """
    tables = []
    offset = 0
    for i, grammar in enumerate(grammars):
        table, offset = VarTable.parse(
            payload, offset, grammar, "%s#%d" % (source, i))
        tables.append(table)
    if offset != len(payload):
        raise EdfError(
            "%s: the grammar consumed %d of %d payload bytes, leaving %d -- a "
            "grammar that does not close on the last byte was read at the "
            "wrong offset"
            % (source, offset, len(payload), len(payload) - offset))
    return tables


def build_var_tables(tables):
    """Rebuild a count-only payload from `VarTable`s."""
    out = bytearray()
    for table in tables:
        out += table.to_bytes()
    return bytes(out)


def write_grammar_json(grammar, path, table_name="", source=""):
    """Freeze a grammar beside its CSV, as write_schema_json does a schema.

    `fixed_bytes` and `variable_fields` are redundant with the field list on
    purpose: a hand-edit that breaks the layout is caught on read rather than
    rebuilding a plausible-looking wrong payload.
    """
    widths = [field_width(t) for _, t in grammar]
    doc = {
        "table": table_name,
        "grammar_source": source,
        "field_count": len(grammar),
        "fixed_bytes": sum(w for w in widths if w is not None),
        "variable_fields": sum(1 for w in widths if w is None),
        "fields": [{"name": n, "type": t} for n, t in grammar],
    }
    with open(path, "w", encoding="ascii", newline="\n") as f:
        json.dump(doc, f, indent=1)
        f.write("\n")


def read_grammar_json(path):
    with open(path, "r", encoding="ascii") as f:
        doc = json.load(f)
    grammar = [(fld["name"], fld["type"]) for fld in doc["fields"]]
    verify_grammar(grammar, os.path.basename(path))
    widths = [field_width(t) for _, t in grammar]
    fixed = sum(w for w in widths if w is not None)
    variable = sum(1 for w in widths if w is None)
    if (len(grammar) != doc["field_count"] or fixed != doc["fixed_bytes"]
            or variable != doc["variable_fields"]):
        raise EdfError(
            "%s is inconsistent: the fields list gives %d fields / %d fixed "
            "bytes / %d variable, the header says %d / %d / %d"
            % (os.path.basename(path), len(grammar), fixed, variable,
               doc["field_count"], doc["fixed_bytes"], doc["variable_fields"]))
    return grammar, doc

def _csv_round_trip(tables, name, tmp, build):
    """Write every table out as CSV + frozen layout, read it back, rebuild.

    All three payload models come through here, and each one freezes the
    layout its own reader needs -- a schema for a chain or .dat table, a
    grammar for a variable-record one. `build` is the matching payload
    builder, passed in rather than sniffed: a chain table and a .dat table are
    both `rf_dat.Table`s and differ only in the header they are written back
    with, so the caller has to say which one it read.
    """
    rebuilt = []
    for i, table in enumerate(tables):
        csv_path = os.path.join(tmp, "%02d.csv" % i)
        layout_path = os.path.join(tmp, "%02d.json" % i)
        table.export_csv(csv_path)
        if isinstance(table, VarTable):
            write_grammar_json(table.grammar, layout_path,
                               table_name="%s#%d" % (name, i),
                               source=table.grammar_source)
            grammar, _doc = read_grammar_json(layout_path)
            rebuilt.append(VarTable.from_csv(csv_path, grammar))
        else:
            write_schema_json(table.schema, layout_path,
                              dat_name="%s#%d" % (name, i),
                              source=table.schema_source,
                              header_field_count=table.field_count)
            schema, doc = read_schema_json(layout_path)
            rebuilt.append(Table.from_csv(
                csv_path, schema, field_count=doc.get("header_field_count")))
    return build(rebuilt)


def _check_tables(paths):
    """payload -> tables -> CSV+layout -> tables -> payload, diffed byte for byte.

    The CSV hop is the point. Parsing a payload proves only that the bytes
    fit; writing the rows out as text, reading them back through the frozen
    layout, and reproducing the payload to the byte is what makes a file safe
    to *edit*. A file matching none of the three readings is reported as
    unhandled, never silently accepted.
    """
    counts = {"chain": 0, "grammar": 0, "dat": 0}
    failed = skipped = 0
    for path in paths:
        name = os.path.basename(path)
        try:
            payload, _key = decrypt_file(path)
        except EdfError as exc:
            print("ERROR  %-28s %s" % (name, exc))
            failed += 1
            continue
        grammar = grammar_for(name)
        try:
            if grammar is not None:
                kind, tables, build = ("grammar",
                                       parse_var_tables(payload, grammar, name),
                                       build_var_tables)
            else:
                kind, tables, build = ("chain",
                                       parse_table_chain(payload, name),
                                       build_table_chain)
        except SchemaError as exc:
            if grammar is not None:
                # A registered grammar that no longer fits is a failure, not a
                # skip: something is wrong with the grammar or with the file,
                # and either way it must not pass quietly.
                print("FAIL   %-28s its grammar does not fit: %s"
                      % (name, str(exc).split(": ", 1)[-1]))
                failed += 1
                continue
            chain_why = str(exc)
            try:
                kind, tables, build = ("dat",
                                       parse_dat_tables(payload, name),
                                       build_dat_tables)
            except SchemaError:
                # Reported against the chain reading: it is the one that gets
                # furthest into these payloads, so its message says the most
                # about where the walk broke.
                print("SKIP   %-28s not a table chain: %s"
                      % (name, chain_why.split(": ", 1)[-1]))
                skipped += 1
                continue
        try:
            with tempfile.TemporaryDirectory() as tmp:
                blob = _csv_round_trip(tables, name, tmp, build)
        except (SchemaError, ValueError, OSError) as exc:
            print("FAIL   %-28s %s" % (name, exc))
            failed += 1
            continue
        if blob == payload:
            print("OK     %-28s %-8s %8d bytes  %2d table(s), %d row(s)"
                  % (name, kind, len(payload),
                     len(tables), sum(len(t.rows) for t in tables)))
            counts[kind] += 1
        else:
            where = next((i for i in range(min(len(blob), len(payload)))
                          if blob[i] != payload[i]), min(len(blob), len(payload)))
            print("FAIL   %-28s rebuilt payload is %d bytes vs %d, first "
                  "difference at offset %d"
                  % (name, len(blob), len(payload), where))
            failed += 1
    print("\n%d payload(s) round-trip byte-exact through CSV (%d chain, "
          "%d grammar, %d dat), %d failed, %d unhandled"
          % (sum(counts.values()), counts["chain"], counts["grammar"],
             counts["dat"], failed, skipped))
    return 1 if failed else 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("file", nargs="+",
                        help="the .edf file(s) to read, or the payload to --encode")
    parser.add_argument("--check", action="store_true",
                        help="decode then re-encode each file and diff against the original")
    parser.add_argument("--classify", action="store_true",
                        help="report which of the three payload readings each file takes, and why none fits if so")
    parser.add_argument("--check-tables", action="store_true",
                        help="round-trip each readable payload through CSV and diff the bytes")
    parser.add_argument("--encode", action="store_true",
                        help="build a .edf from a decoded payload (needs --key)")
    parser.add_argument("--key", help="file holding the 256-byte decoded key, for --encode")
    parser.add_argument("--out", help="write the payload (or the rebuilt .edf) here")
    parser.add_argument("--key-out", help="write the decoded 256-byte key here")
    args = parser.parse_args(argv)

    if args.encode:
        if len(args.file) != 1 or not args.key or not args.out:
            parser.error("--encode takes exactly one payload file, --key and --out")
        with open(args.file[0], "rb") as f:
            payload = f.read()
        with open(args.key, "rb") as f:
            key = f.read()
        with open(args.out, "wb") as f:
            f.write(encrypt(payload, key))
        print("wrote %s" % args.out)
        return 0

    if args.classify:
        chains = grammars = dats = 0
        for path in args.file:
            name = os.path.basename(path)
            try:
                payload, _key = decrypt_file(path)
            except EdfError as exc:
                print("ERROR  %-28s %s" % (name, exc))
                continue
            grammar = grammar_for(name)
            if grammar is not None:
                try:
                    tables = parse_var_tables(payload, grammar, name)
                except SchemaError as exc:
                    print("BROKEN %-28s %8d bytes  its grammar does not fit: %s"
                          % (name, len(payload), str(exc).split(": ", 1)[-1]))
                    continue
                grammars += 1
                print("GRAMMR %-28s %8d bytes  %2d table(s)  %s"
                      % (name, len(payload), len(tables),
                         ", ".join("%d rec" % len(t.rows) for t in tables)))
                continue
            layout, why = classify(payload, name)
            if layout:
                chains += 1
                print("CHAIN  %-28s %8d bytes  %2d table(s)  %s"
                      % (name, len(payload), len(layout),
                         ", ".join("%dx%d" % (c, r) for c, r in layout[:6])
                         + (", ..." if len(layout) > 6 else "")))
                continue
            try:
                tables = parse_dat_tables(payload, name)
            except SchemaError:
                print("OTHER  %-28s %8d bytes  %s"
                      % (name, len(payload), why.split(": ", 1)[-1]))
                continue
            dats += 1
            print("DAT    %-28s %8d bytes  %2d table(s)  %s"
                  % (name, len(payload), len(tables),
                     ", ".join("%dx%d in %d field(s)"
                               % (len(t.rows), t.rec_size, t.field_count)
                               for t in tables[:4])))
        print("\n%d/%d payload(s) are table chains, %d have a hand-derived "
              "grammar, %d are plain .dat containers"
              % (chains, len(args.file), grammars, dats))
        return 0

    if args.check_tables:
        return _check_tables(args.file)

    if args.check:
        failures = 0
        for path in args.file:
            with open(path, "rb") as f:
                original = f.read()
            try:
                payload, key = decrypt(original)
            except EdfError as exc:
                print("FAIL   %s: %s" % (path, exc))
                failures += 1
                continue
            if encrypt(payload, key) == original:
                print("OK     %s (%d-byte payload)" % (path, len(payload)))
            else:
                print("FAIL   %s: re-encoding does not reproduce the original bytes" % path)
                failures += 1
        print("\n%d/%d file(s) round-trip byte-exact" % (len(args.file) - failures, len(args.file)))
        return 1 if failures else 0

    if len(args.file) != 1:
        parser.error("pass a single file unless you are using --check")
    payload, key = decrypt_file(args.file[0])
    if args.key_out:
        with open(args.key_out, "wb") as f:
            f.write(key)
    if args.out:
        with open(args.out, "wb") as f:
            f.write(payload)
        print("wrote %d bytes to %s" % (len(payload), args.out))
    else:
        sys.stdout.buffer.write(payload)
    return 0


if __name__ == "__main__":
    sys.exit(main())
