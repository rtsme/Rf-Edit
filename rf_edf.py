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
field may be fixed-width or variable-width. `NDLanguage.edf` and
`NDStore.edf` have one.

BACKLOG #52 added the second grammar shape, for records that nest: a
`BlockGrammar` is a block header, a count, and that many items of their own
field list. `en-ph/Hint.edf` is one -- 67 hints, each a header and between one
and seven separately coloured runs of text -- and it needs a `<u16 len>`
string kind (`WPSTR`) that the flat grammars had no use for.
`en-ph/UIHelp.edf` is the same runs of text again, in 55 such tables laid end
to end. A block table
writes two CSVs, blocks and items, joined by a `Block` column; the nested
count is derived from the item rows, never carried in a column.

BACKLOG #52 then found that two of the 13 left over are not a third structure
at all: `en-ph/Exp.edf` and `en-ph/Player.edf` are the server's **plain .dat
container** -- the full 12-byte `<count><field_count><record_size>` header --
sitting inside the `.edf` encryption unchanged. They broke the chain walk only
because it reads eight bytes where they write twelve. That extra `field_count`
is what makes them readable without disassembling anything: `parse_dat_tables`
refuses unless a schema inferred from the record bytes alone comes out with
exactly the number of fields the header declares.

The remaining 9 stay opaque blobs until someone reads the client's reader for
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
        # Hint.edf reads the same way; its one table is a BlockTable, with
        # `rows` the 67 hints and `items` their runs of text.

    from rf_edf import parse_dat_tables, build_dat_tables
        tables = parse_dat_tables(payload, "Player.edf")
        assert build_dat_tables(tables) == payload
"""
import argparse
import collections
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

# `<u16 len><len bytes>`, with **no** terminator inside the count -- the string
# shape BACKLOG #52 derived in `Hint.edf`. A different contract from LPSTR's,
# and deliberately a separate kind rather than a width option on it: over
# there the terminator is what lets one string, on its own, say whether the
# grammar fits. Here nothing does, so the claim rests entirely on the walk --
# a field boundary wrong by one byte makes the next `<u16 len>` read garbage
# and the table stops short of the last payload byte. The length is derived
# from the text on write, exactly as LPSTR's is.
WPSTR = "wpstr"

# What a 2-byte prefix can say. Editing a string past it is an error rather
# than a silent truncation: the record would rebuild short and every byte
# after it would move.
MAX_WPSTR = 0xFFFF

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
    if ftype in (LPSTR, WPSTR):
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
    if ftype == WPSTR:
        if pos + 2 > len(data):
            raise EdfError("%s: no room for the 2-byte length prefix" % where)
        length = struct.unpack_from("<H", data, pos)[0]
        pos += 2
        if pos + length > len(data):
            raise EdfError("%s: length prefix says %d bytes, %d past the end "
                           "of the table"
                           % (where, length, pos + length - len(data)))
        return data[pos:pos + length].decode("latin-1"), pos + length
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
    if ftype == WPSTR:
        raw = str(value).encode("latin-1")
        if len(raw) > MAX_WPSTR:
            raise ValueError("too long: %d bytes, a 2-byte length prefix "
                             "holds %d" % (len(raw), MAX_WPSTR))
        return struct.pack("<H", len(raw)) + raw
    return encode(value, ftype)


def parse_field(text, ftype):
    """Turn CSV text into a value `write_field` will accept, or raise."""
    m = _ZSTR_RE.match(ftype)
    if m or ftype in (LPSTR, WPSTR):
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
        if ftype == WPSTR and len(raw) > MAX_WPSTR:
            raise ValueError("too long: %d bytes, a 2-byte length prefix "
                             "holds %d" % (len(raw), MAX_WPSTR))
        return text
    return parse_value(text, ftype)


# A **block** grammar: BACKLOG #52's second shape, for a table whose records
# are not one flat field list but a header, a count, and that many nested
# items -- Hint.edf's 67 hints, each a fixed header and between one and seven
# coloured runs of text.
#
# The count is a field of the file and *not* a field of the grammar: it sits
# between `block` and the items, and it is written from the number of item
# rows rather than carried in a column. Same reason LPSTR's length is derived:
# a number a person has to keep in step by hand is a number that eventually is
# not, and here disagreeing with it would not truncate one string, it would
# move every byte in the rest of the table.
BlockGrammar = collections.namedtuple("BlockGrammar", "block count item")

# What the item count may be. Anything wider is a record count, not an item
# count, and reading one as the other would mean the shape was read wrong.
BLOCK_COUNT_TYPES = ("ubyte", "uword", "udword")

# The items CSV's first column: which block the row belongs to. It is the join
# between the two files, so no item field may share the name.
BLOCK_COLUMN = "Block"


def _verify_fields(grammar, source):
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


def verify_grammar(grammar, source="grammar"):
    """Reject a grammar that could not produce a usable CSV. Returns it."""
    if isinstance(grammar, BlockGrammar):
        if grammar.count not in BLOCK_COUNT_TYPES:
            raise EdfError("%s: %r is not an item-count type (%s)"
                           % (source, grammar.count,
                              ", ".join(BLOCK_COUNT_TYPES)))
        _verify_fields(grammar.block, "%s block header" % source)
        _verify_fields(grammar.item, "%s item" % source)
        if any(n == BLOCK_COLUMN for n, _ in grammar.item):
            raise EdfError("%s: an item field may not be called %r -- that "
                           "column carries the block number"
                           % (source, BLOCK_COLUMN))
        return grammar
    return _verify_fields(grammar, source)


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
    # BACKLOG #52. <u32 67> then 67 hints; a hint is a 19-byte header, a <u8>
    # count of text runs, and that many runs of 12 fixed bytes and a <u16 len>
    # string. The walk closes exactly on the last of 8998 payload bytes, and
    # it is the *only* one that does: sweeping header width 1..47 x count
    # width 1/2/4 x run prefix 4..19 leaves this one layout standing, and the
    # 67 it reads is the count the file declares at offset 0.
    #
    # What the search cannot pin is where one *fixed* field ends and the next
    # begins, and that is a question of labels only -- any partition of the
    # same fixed bytes rebuilds the same bytes. Two readings are still worth
    # the names they carry:
    #   - `Duration` -- 15000 in 66 of the 67 headers and 5000 in the other.
    #     Round millisecond values, and the offset is forced: at any other
    #     start those bytes are not a round number.
    #   - the run's `Color*` -- ffffffff, 00ff00ff, 8000ffff, a0a0a0ff,
    #     0000ffff, i.e. white / green / purple / grey / blue, always with an
    #     opaque last byte. Four bytes that vary together as RGBA across both
    #     this file and UIHelp.edf.
    # Everything left is numbered rather than guessed at, the way NDStore's
    # two names are. `Unknown3` is 0xCDCD in all 235 runs -- MSVC's
    # uninitialised-stack fill, so it is a field the client writes and never
    # sets, and one nobody should read meaning into.
    "hint.edf": [
        BlockGrammar(
            block=[("Id", "dword"),
                   ("ColorR", "ubyte"), ("ColorG", "ubyte"),
                   ("ColorB", "ubyte"),
                   ("Unknown1", "udword"), ("Duration", "udword"),
                   ("Unknown2", "udword")],
            count="ubyte",
            item=[("Unknown1", "ubyte"), ("Unknown2", "ubyte"),
                  ("Unknown3", "uword"),
                  ("ColorR", "ubyte"), ("ColorG", "ubyte"),
                  ("ColorB", "ubyte"), ("ColorA", "ubyte"),
                  ("Unknown4", "dword"), ("Text", WPSTR)]),
    ],
    # BACKLOG #52. The same runs of text as Hint.edf, in 55 tables laid end to
    # end -- one per UI window, and no count in front of them, so the number of
    # tables is what the walk proves rather than something the file says: 54
    # stops 1537 bytes short and 56 runs off the end.
    #
    # What says the table boundaries are right is `Index`. In each of the 20
    # tables that has a bound block, that block's second field is the table's
    # own position in the sequence -- 0, 1, 5, 6, 7, 9, ... 47 -- counting the
    # 28 empty tables in between. Twenty independent agreements between a
    # number in the file and a number only the walk knows; the same class of
    # cross-check as NDStore.edf's 278 records matching Store.edf's. Table 54's
    # nine blocks carry -1 in all three header fields: text bound to no window.
    "uihelp.edf": [
        BlockGrammar(
            block=[("Id", "dword"), ("Index", "dword"),
                   ("Unknown1", "dword")],
            count="ubyte",
            item=[("Unknown1", "ubyte"), ("Unknown2", "ubyte"),
                  ("Unknown3", "uword"),
                  ("ColorR", "ubyte"), ("ColorG", "ubyte"),
                  ("ColorB", "ubyte"), ("ColorA", "ubyte"),
                  ("Unknown4", "dword"), ("Text", WPSTR)]),
    ] * 55,
    # BACKLOG #52. Two parallel runs of 45 count-only tables -- 45 tables of
    # fixed 64-byte item names, then 45 tables of the matching descriptions --
    # and one last table of 100 mission entries. The walk closes exactly on
    # the last of 8 130 085 payload bytes.
    #
    # **What makes the two runs a derivation and not a guess is that they are
    # the same length.** Nothing in the file says 45; it is what the walk
    # arrives at from offset 0 twice over, independently, reading two
    # different record shapes. A boundary wrong anywhere in the first run
    # would land the second run's first table on bytes that are not a count,
    # and 45 = 45 would not survive it. The two runs are also the same
    # categories in the same order: name table 12 is the eight tool kits
    # (`Weapon/Shield Tool Kit`, `Armor Tool Kit`, ...) and description table
    # 11 is those same eight, described. The runs are offset by one because
    # the first name table -- 80 character faces -- has no descriptions, and
    # correspondingly the description run ends with two empty tables where the
    # name run ends with one.
    #
    # A name table is `<u32 count>` then `count` x 64 NUL-padded bytes, and a
    # description table `<u32 count>` then `count` x (`<u32 id><u32 0>
    # <u32 len><len bytes>`) with `id` running 0..count-1 -- the same
    # self-checking index NDLanguage.edf has, holding for all 45 tables. The
    # zero dword between the id and the string is numbered, not named: it is
    # zero in every record of every table, which is exactly as consistent
    # with padding as with a field nothing in this file ever sets.
    "nditem.edf": (
        [[("Name", "zstr[64]")]] * 45
        + [[("Id", "dword"), ("Unknown1", "dword"), ("Text", LPSTR)]] * 45
        # The 91st table: `<u32 100>` then 100 x (`<u32 index><zstr[4] code>`,
        # 60 fixed bytes, `<u32 len><len bytes>`). `index` runs 0..99 and
        # `code` runs `a1`..`a100`, so each record start is pinned twice over
        # by the file itself; within a record the split is forced too, since
        # exactly one offset in each of the 100 records has a length prefix
        # that reaches the next record start, and all 100 agree on 60.
        #
        # That 60 is **fixed**, which is the point the earlier note in
        # docs/knowledge/edf-payload-tables.md got wrong: it read the region
        # as a variable-length list, and it does not vary. So the 15 dwords
        # need no new field kind -- they are ordinary fixed fields.
        #
        # They are numbered rather than named because their roles cannot be
        # pinned from this file. Eight of the fifteen carry values and the
        # seven between them are zero; four of the eight are a run of
        # consecutive text ids, which across the table climb strictly from
        # 1853 to 2500. But *which* four alternates with the record's parity
        # -- even records carry the ids in `Unknown1/3/5/7`, odd records in
        # `Unknown2/4/6/8`, an ABAB run unbroken across all 100. Until
        # something explains that alternation, naming a slot would be
        # asserting a role the file contradicts every other record. Record 28
        # is the one exception to every pattern here, carrying uninitialised
        # bytes in slots that are zero in the other 99 -- the same kind of
        # client-side junk as Hint.edf's 0xCDCD, and harmless: fixed bytes
        # round-trip whatever they hold.
        + [[("Id", "dword"), ("Code", "zstr[4]")]
           + [("Unknown%d" % i, "dword") for i in range(1, 16)]
           + [("Text", LPSTR)]]
    ),
}


def grammar_for(source):
    """The table grammars for a file name, or None if it has none."""
    return EDF_TABLE_GRAMMARS.get(os.path.basename(source).lower())


def _write_csv(path, header, rows):
    """One line per record, ASCII-only, LF endings -- as rf_dat.Table."""
    with open(path, "w", newline="", encoding="ascii") as f:
        w = csv.writer(f, lineterminator="\n")
        w.writerow(header)
        for row in rows:
            w.writerow(row)


def _read_csv(path, grammar, lead=None):
    """Read a CSV whose columns are exactly `grammar`, after an optional
    leading `lead` column of integers. Returns `(lead values, rows)`.
    """
    where = os.path.basename(path)
    expected = ([lead] if lead else []) + [n for n, _ in grammar]
    leads, rows = [], []
    with open(path, "r", newline="", encoding="ascii") as f:
        reader = csv.reader(f)
        try:
            header = next(reader)
        except StopIteration:
            raise ValueError("%s is empty" % where)
        if header != expected:
            raise ValueError(
                "%s: columns don't match the grammar.\nexpected %d columns "
                "starting %s\ngot %d columns starting %s\nColumns must not "
                "be added, removed or reordered -- they are the record "
                "layout." % (where, len(expected), expected[:4],
                             len(header), header[:4]))
        for i, rec in enumerate(reader):
            if len(rec) != len(expected):
                raise ValueError("%s line %d: has %d values, expected %d"
                                 % (where, i + 2, len(rec), len(expected)))
            if lead:
                try:
                    leads.append(int(rec[0]))
                except ValueError:
                    raise ValueError("%s line %d, column %s: %r is not a "
                                     "block number"
                                     % (where, i + 2, lead, rec[0]))
                rec = rec[1:]
            row = {}
            for (name, ftype), text in zip(grammar, rec):
                try:
                    row[name] = parse_field(unescape_text(text), ftype)
                except ValueError as exc:
                    raise ValueError("%s line %d, column %s: %s"
                                     % (where, i + 2, name, exc))
            rows.append(row)
    return leads, rows


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
        names = [n for n, _ in self.grammar]
        _write_csv(path, names,
                   ([escape_text(str(row[n])) for n in names]
                    for row in self.rows))

    def import_csv(self, path):
        _leads, rows = _read_csv(path, self.grammar)
        self.rows = rows
        return rows


class BlockTable(object):
    """One count-only table whose records nest a second, counted list.

    `<u32 block_count>`, then per block the header fields, an item count, and
    that many items. Two levels, so two CSVs: the blocks in the file the
    caller names and the items beside it as `<name>.items.csv`, joined by a
    `Block` column. Flattening them into one file would mean repeating every
    header value on every item row, and a file where the same fact is written
    many times is a file where an edit can disagree with itself.

    Item order inside a block is byte order, so the items CSV is read in the
    order it is written: rows must stay grouped and in block order, and the
    importer says so rather than quietly reshuffling the payload.
    """

    def __init__(self, grammar, rows, items, source=None, grammar_source=None):
        self.grammar = verify_grammar(grammar, source or "grammar")
        if len(rows) != len(items):
            raise EdfError("%s: %d block(s) but %d item list(s)"
                           % (source or "table", len(rows), len(items)))
        self.rows = rows
        self.items = items
        self.source = source
        self.grammar_source = grammar_source

    @staticmethod
    def items_path(path):
        """Where the item rows live, given the block CSV's path."""
        base, ext = os.path.splitext(path)
        return base + ".items" + (ext or ".csv")

    @classmethod
    def parse(cls, data, offset, grammar, source):
        """Read `<u32 count>` and its blocks at `offset`.

        Returns the table and the offset just past it.
        """
        verify_grammar(grammar, source)
        if offset + COUNT_HEADER_SIZE > len(data):
            raise EdfError("%s: %d byte(s) left, too few for a 4-byte block "
                           "count" % (source, len(data) - offset))
        count = struct.unpack_from(COUNT_HEADER, data, offset)[0]
        pos = offset + COUNT_HEADER_SIZE
        if count > MAX_RECORD_COUNT:
            raise EdfError("%s: reads as %d blocks, which is not a block "
                           "count" % (source, count))
        rows, items = [], []
        for i in range(count):
            row = {}
            for name, ftype in grammar.block:
                row[name], pos = read_field(
                    data, pos, ftype,
                    "%s block %d field %s" % (source, i, name))
            n, pos = read_field(data, pos, grammar.count,
                                "%s block %d item count" % (source, i))
            if n < 0 or n > MAX_RECORD_COUNT:
                raise EdfError("%s block %d: reads as %d items, which is not "
                               "an item count" % (source, i, n))
            group = []
            for j in range(n):
                item = {}
                for name, ftype in grammar.item:
                    item[name], pos = read_field(
                        data, pos, ftype,
                        "%s block %d item %d field %s" % (source, i, j, name))
                group.append(item)
            rows.append(row)
            items.append(group)
        return cls(grammar, rows, items, source=source,
                   grammar_source="hand-derived (EDF_TABLE_GRAMMARS)"), pos

    def to_bytes(self):
        where = self.source or "table"
        out = bytearray(struct.pack(COUNT_HEADER, len(self.rows)))
        for i, (row, group) in enumerate(zip(self.rows, self.items)):
            for name, ftype in self.grammar.block:
                try:
                    out += write_field(row[name], ftype)
                except ValueError as exc:
                    raise EdfError("%s block %d field %s: %s"
                                   % (where, i, name, exc))
            try:
                out += write_field(len(group), self.grammar.count)
            except (ValueError, struct.error):
                raise EdfError("%s block %d: %d items is more than this "
                               "file's %s item count can hold"
                               % (where, i, len(group), self.grammar.count))
            for j, item in enumerate(group):
                for name, ftype in self.grammar.item:
                    try:
                        out += write_field(item[name], ftype)
                    except ValueError as exc:
                        raise EdfError("%s block %d item %d field %s: %s"
                                       % (where, i, j, name, exc))
        return bytes(out)

    @classmethod
    def from_csv(cls, csv_path, grammar):
        t = cls(grammar, [], [], source=os.path.basename(csv_path),
                grammar_source=os.path.basename(csv_path))
        t.import_csv(csv_path)
        return t

    def export_csv(self, path):
        names = [n for n, _ in self.grammar.block]
        _write_csv(path, names,
                   ([escape_text(str(row[n])) for n in names]
                    for row in self.rows))
        inames = [n for n, _ in self.grammar.item]
        _write_csv(self.items_path(path), [BLOCK_COLUMN] + inames,
                   ([str(i)] + [escape_text(str(item[n])) for n in inames]
                    for i, group in enumerate(self.items) for item in group))

    def import_csv(self, path):
        _leads, rows = _read_csv(path, self.grammar.block)
        ipath = self.items_path(path)
        leads, items = _read_csv(ipath, self.grammar.item, lead=BLOCK_COLUMN)
        where = os.path.basename(ipath)
        groups = [[] for _ in rows]
        last = -1
        for i, (block, item) in enumerate(zip(leads, items)):
            if not 0 <= block < len(rows):
                raise ValueError("%s line %d: block %d, but %s has %d block(s)"
                                 % (where, i + 2, block,
                                    os.path.basename(path), len(rows)))
            if block < last:
                raise ValueError(
                    "%s line %d: block %d after block %d -- item rows are "
                    "written back in the order they appear, so they must stay "
                    "grouped and in block order"
                    % (where, i + 2, block, last))
            last = block
            groups[block].append(item)
        self.rows = rows
        self.items = groups
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
        reader = BlockTable if isinstance(grammar, BlockGrammar) else VarTable
        table, offset = reader.parse(
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


def _layout_doc(fields, prefix=""):
    widths = [field_width(t) for _, t in fields]
    return {
        prefix + "field_count": len(fields),
        prefix + "fixed_bytes": sum(w for w in widths if w is not None),
        prefix + "variable_fields": sum(1 for w in widths if w is None),
        prefix + "fields": [{"name": n, "type": t} for n, t in fields],
    }


def write_grammar_json(grammar, path, table_name="", source=""):
    """Freeze a grammar beside its CSV, as write_schema_json does a schema.

    `fixed_bytes` and `variable_fields` are redundant with the field list on
    purpose: a hand-edit that breaks the layout is caught on read rather than
    rebuilding a plausible-looking wrong payload. A block grammar freezes both
    of its field lists and the width of the item count between them, for the
    same reason -- there are more numbers to get wrong, not fewer.
    """
    doc = {"table": table_name, "grammar_source": source}
    if isinstance(grammar, BlockGrammar):
        doc["kind"] = "block"
        doc["item_count_type"] = grammar.count
        doc.update(_layout_doc(grammar.block))
        doc.update(_layout_doc(grammar.item, "item_"))
    else:
        doc["kind"] = "flat"
        doc.update(_layout_doc(grammar))
    with open(path, "w", encoding="ascii", newline="\n") as f:
        json.dump(doc, f, indent=1)
        f.write("\n")


def _read_layout(doc, where, prefix=""):
    fields = [(fld["name"], fld["type"]) for fld in doc[prefix + "fields"]]
    _verify_fields(fields, where)
    widths = [field_width(t) for _, t in fields]
    fixed = sum(w for w in widths if w is not None)
    variable = sum(1 for w in widths if w is None)
    if (len(fields) != doc[prefix + "field_count"]
            or fixed != doc[prefix + "fixed_bytes"]
            or variable != doc[prefix + "variable_fields"]):
        raise EdfError(
            "%s is inconsistent: the %sfields list gives %d fields / %d fixed "
            "bytes / %d variable, the header says %d / %d / %d"
            % (where, prefix, len(fields), fixed, variable,
               doc[prefix + "field_count"], doc[prefix + "fixed_bytes"],
               doc[prefix + "variable_fields"]))
    return fields


def read_grammar_json(path):
    with open(path, "r", encoding="ascii") as f:
        doc = json.load(f)
    where = os.path.basename(path)
    if doc.get("kind") == "block":
        grammar = BlockGrammar(_read_layout(doc, where),
                               doc["item_count_type"],
                               _read_layout(doc, where, "item_"))
    else:
        grammar = _read_layout(doc, where)
    verify_grammar(grammar, where)
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
        if isinstance(table, (VarTable, BlockTable)):
            write_grammar_json(table.grammar, layout_path,
                               table_name="%s#%d" % (name, i),
                               source=table.grammar_source)
            grammar, _doc = read_grammar_json(layout_path)
            rebuilt.append(type(table).from_csv(csv_path, grammar))
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
                         ", ".join("%d rec" % len(t.rows)
                                   for t in tables[:6])
                         + (", ..." if len(tables) > 6 else "")))
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
