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

BACKLOG #52 then found two shapes where a record's text is not in the record
at all: it sits in one **pool** after the table, in record order, and the
record holds only its length. `en-ph/NDMsgMonster.edf` is the array form -- a
`PoolGrammar` of twenty length slots and a count of how many are used, so a
monster has a *list* of messages and the table writes two CSVs like a block
one does. `en-ph/NDQuest.edf` is the single form: there the length is one
ordinary fixed field among three dwords (`POOLSTR`), so a string is one
column of one row and there is nothing to join. NDQuest is also the first
file that is chain-shaped in part -- its two tables carry the full 8-byte
header -- which is what `ChainGrammar` reads: a chain-format table with a
hand-written field list, checked against the record size the file itself
states.

BACKLOG #52 last found a file that is chain-shaped for most of its length and
count-only for the rest: `en-ph/GameData.edf` is eight ordinary chain tables
-- the first seven of them `EventShip.edf`'s whole payload, table for table --
and then one table of flying-ship announcements the chain walk cannot read.
One count-only table at the end is enough to stop `parse_table_chain` at
offset 0, so those eight need a way to say "read this the way a chain file is
read", which is `INFERRED_CHAIN`: the only entry in `EDF_TABLE_GRAMMARS` that
is not a hand-derived layout, because there is nothing there to derive.
`en-ph/NDEventShip.edf` is the same file localised, and carries the same 61
announcements -- which is what proves the reading of both.

The remaining 4 stay opaque blobs until someone reads the client's reader for
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
# these two closes under the chain walk or has a grammar, so the four
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
# the fourth payload: a chain whose tables each carry a 10-byte stamp
# --------------------------------------------------------------------------
#
# BACKLOG #52, eighth session. `Item.edf` is the last file the other three
# readings reject, and the reason is a wrapper, not a record layout: it *is* a
# table chain, but every table is preceded by ten bytes the chain walk knows
# nothing about, so `chain_layout` reads the stamp as a count and a size and
# stops at offset 0. Hence the old note that the payload "starts `00 f1 c8 30`,
# a value, not a header" -- it is a header, just not the one being looked for.
#
#     <u8 index> <u8 0xf1> <u32 body_length> <u32 own_offset>   10-byte stamp
#     body_length bytes                                         the body
#
# and a table body is the ordinary chain table the other 17 files are made of:
#
#     <u32 record_count> <u32 record_size>
#     record_count * record_size bytes
#
# **Two redundant numbers are what make this a derivation rather than a
# guess.** The stamp states its own offset, which must equal where the walk
# already is, and a body length, which must equal `8 + count * size` computed
# from numbers stored four and eight bytes further on. Neither is needed to
# read the file; both have to agree at every block or the walk is wrong. They
# agree at all 47, and the walk closes on the last of 15 199 742 bytes.
#
# The third agreement is in a different file. `Item.edf`'s first 44 tables
# hold 80, 7469, 7469, 7469, 7469, 8099, 10642, 1846, ... records, and those
# are, in order and exactly, the record counts of the 44 name tables of
# `en-ph/NDItem.edf` -- a file read by a wholly unrelated grammar. Item data
# and item names, table for table. Nothing in this walk used `NDItem.edf`, so
# 44 independent agreements are as strong a check as this layer has had.
#
# The 47th and last block is not a table: its body is 368 bytes that do not
# satisfy `8 + count * size`, so the reading does not force them to. A block
# whose body length matches is read as a chain table; one that does not is
# kept as a single fixed record, which is the honest description of a footer
# whose meaning is not derived. It reads as 92 dwords -- two arrays of 46, one
# entry per data block, whose non-zero entries land on the same handful of
# tables in both halves. What the two arrays are *for* is not known, and the
# reading claims nothing about it.
#
# The stamp's index byte runs 0..45 for the data tables and is 47 on the
# footer: 46 is not used by this file. Nothing in the payload derives that, so
# it is carried per table rather than recomputed, the way a `.dat` table's
# `header_field_count` is.

STAMP_MAGIC = 0xF1
STAMP_HEADER = "<BBII"
STAMP_HEADER_SIZE = struct.calcsize(STAMP_HEADER)
assert STAMP_HEADER_SIZE == 10


def stamp_layout(payload, source="EDF payload"):
    """Return `[(index, body_length, offset), ...]` for a stamped payload.

    Structure only, like `chain_layout`, and strict for its reason: a stamp
    that does not state its own offset, or a walk that does not end on the
    last byte, means the stamps are being read at the wrong places and every
    body after that point is garbage.
    """
    layout = []
    offset = 0
    while offset < len(payload):
        if len(payload) - offset < STAMP_HEADER_SIZE:
            raise EdfError(
                "%s: %d byte(s) left after block %d -- too few for another "
                "%d-byte stamp"
                % (source, len(payload) - offset, len(layout),
                   STAMP_HEADER_SIZE))
        index, magic, body, own = struct.unpack_from(
            STAMP_HEADER, payload, offset)
        if magic != STAMP_MAGIC:
            raise EdfError(
                "%s block %d at offset %d: second stamp byte is 0x%02x, not "
                "0x%02x" % (source, len(layout), offset, magic, STAMP_MAGIC))
        if own != offset:
            raise EdfError(
                "%s block %d: its stamp says it starts at %d, but the walk is "
                "at %d" % (source, len(layout), own, offset))
        end = offset + STAMP_HEADER_SIZE + body
        if end > len(payload):
            raise EdfError(
                "%s block %d at offset %d: a %d-byte body runs %d byte(s) "
                "past the end of the payload"
                % (source, len(layout), offset, body, end - len(payload)))
        layout.append((index, body, offset))
        offset = end
    if not layout:
        raise EdfError("%s: no blocks" % source)
    return layout


class StampTable(object):
    """One stamped block: the stamp's index and the table in its body.

    Deliberately thin. The body is an ordinary `rf_dat.Table` and does all the
    CSV work; this only remembers the two things the body cannot state -- the
    stamp's index byte, and whether the body carries the 8-byte chain header
    (a data table) or is a single bare record (the footer).
    """

    def __init__(self, index, table, headed, source=None):
        self.index = index
        self.table = table
        self.headed = headed
        self.source = source
        self.offset = 0

    @property
    def rows(self):
        return self.table.rows

    @property
    def schema(self):
        return self.table.schema

    @property
    def schema_source(self):
        return self.table.schema_source

    @classmethod
    def parse(cls, payload, index, body, offset, source):
        data = payload[offset + STAMP_HEADER_SIZE:
                       offset + STAMP_HEADER_SIZE + body]
        if body >= CHAIN_HEADER_SIZE:
            count, rec_size = struct.unpack_from(CHAIN_HEADER, data, 0)
            if body == CHAIN_HEADER_SIZE + count * rec_size:
                return cls(index,
                           _table_from_records(data[CHAIN_HEADER_SIZE:],
                                               count, rec_size, source),
                           True, source=source)
        # Not a chain table. One fixed record, read as numbers: inferring a
        # schema from a single record invents string columns out of runs of
        # zero bytes, which is a claim about bytes that are not there -- the
        # same reason `_table_from_records` refuses to infer from no records.
        if body % 4:
            raise EdfError(
                "%s: a %d-byte body is neither a chain table nor a whole "
                "number of dwords, so there is no evidence for any layout"
                % (source, body))
        schema = [("Val%d" % (i + 1), "dword") for i in range(body // 4)]
        verify_schema(schema, len(schema), body)
        row = {}
        for i, (name, ftype) in enumerate(schema):
            row[name] = decode(data[i * 4:(i + 1) * 4], ftype)
        return cls(index,
                   Table(schema, [row], len(schema), body, source=source,
                         schema_source="dwords (body is not a chain table)",
                         strict_field_count=False),
                   False, source=source)

    def to_bytes(self):
        body = self.table.to_bytes()[HEADER_SIZE:]
        if self.headed:
            body = struct.pack(CHAIN_HEADER, len(self.table.rows),
                               self.table.rec_size) + body
        return (struct.pack(STAMP_HEADER, self.index, STAMP_MAGIC,
                            len(body), self.offset) + body)

    def export_csv(self, path):
        self.table.export_csv(path)

    @classmethod
    def from_csv(cls, csv_path, schema, index, headed, field_count=None):
        return cls(index,
                   Table.from_csv(csv_path, schema, field_count=field_count),
                   headed, source=os.path.basename(csv_path))


class StampedDirectoryError(EdfError):
    """A stamped payload whose footer and its target block disagree.

    Distinct from a plain `EdfError` so a caller can tell "this is not a
    stamped payload at all" from "this is one, and its two halves contradict
    each other" -- a skip and a failure, which are not the same report.
    """


def check_stamped_directory(tables, source="EDF payload"):
    """Refuse a stamped payload whose footer disagrees with the block it indexes.

    BACKLOG #60 derived two redundancies in `Item.edf`'s footer and #61 checks
    them, for the reason the rest of this layer checks its redundant numbers:
    an edit that adds a row to the indexed block without fixing the directory
    rebuilds *byte-exactly* and hands the client a file whose directory points
    at the wrong rows. The round trip cannot see that. Nothing else would.

    The footer is two parallel arrays of one entry per data block -- a first
    row and a row count -- naming slices of one other block. The checks are:

      * the non-empty ranges tile that block exactly: contiguous from row 0,
        no gap and no overlap;
      * every row of it carries, in its second field, the index of the block
        whose range contains it. Its first field is the row's own number.

    Deliberately shape-guarded rather than named: a payload that is stamped
    but carries no footer of this shape is left alone, because there is only
    one file in this format and a check that fired on a different one would be
    a claim about bytes nobody has read. What is *not* softened is the case
    where the shape does match and the contents disagree.

    This is a read check. The directory is never recomputed on write: a
    rebuild that silently rewrote it would hide the bad edit instead of
    catching it, which is the opposite of the point.
    """
    footers = [t for t in tables if not t.headed]
    headed = [t for t in tables if t.headed]
    if len(footers) != 1 or not headed:
        return
    footer = footers[0]
    if len(footer.rows) != 1:
        return
    values = [footer.rows[0][name] for name, _ in footer.schema]
    if len(values) != 2 * len(headed):
        return
    half = len(headed)
    first, length = values[:half], values[half:]
    if any(n < 0 for n in first) or any(n < 0 for n in length):
        raise StampedDirectoryError(
            "%s: its directory has a negative row number or row count" % source)
    owners = [i for i in range(half) if length[i]]
    if not owners:
        return

    # The ranges have to tile, contiguous from row 0.
    at = 0
    for i in sorted(owners, key=lambda i: first[i]):
        if first[i] != at:
            raise StampedDirectoryError(
                "%s: block %d's slice starts at row %d, but the slice before "
                "it ends at row %d -- the directory's ranges must be "
                "contiguous from row 0 with no gap and no overlap"
                % (source, i, first[i], at))
        at += length[i]

    # The block they tile is the one with exactly that many rows. If that does
    # not pick out a single block there is nothing to compare against, and
    # guessing which one was meant would be the sort of claim this refuses.
    targets = [i for i, t in enumerate(headed) if len(t.rows) == at]
    if len(targets) != 1:
        return
    target = headed[targets[0]]
    if len(target.schema) < 2:
        return
    owner_field = target.schema[1][0]

    owner_of = {}
    for i in owners:
        for row in range(first[i], first[i] + length[i]):
            owner_of[row] = i
    for row, values in enumerate(target.rows):
        if values[owner_field] != owner_of[row]:
            raise StampedDirectoryError(
                "%s: block %d row %d says it belongs to block %s, but the "
                "directory puts that row in block %d's slice"
                % (source, targets[0], row, values[owner_field],
                   owner_of[row]))


def parse_stamped_tables(payload, source="EDF payload"):
    """Parse a stamped payload into `StampTable`s, consuming every byte."""
    tables = []
    for index, body, offset in stamp_layout(payload, source):
        tables.append(StampTable.parse(
            payload, index, body, offset, "%s#%d" % (source, len(tables))))
    check_stamped_directory(tables, source)
    return tables


def build_stamped_tables(tables):
    """Rebuild a stamped payload from `StampTable`s.

    Each stamp's own-offset is written from where the block actually lands, not
    from what was read: it is derived, so a rebuild is self-consistent even if
    a table above it changed size.
    """
    out = bytearray()
    for table in tables:
        table.offset = len(out)
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

# `<u32 len>` in the record, and the bytes it measures **not** in the record:
# they sit in one pool after the table, in record order. BACKLOG #52 derived
# this in NDQuest.edf, where a quest's text is one field among three ordinary
# dwords.
#
# The terminator is counted in the length and the CSV holds the text without
# it -- LPSTR's contract exactly, and read with the same check, so a pooled
# string is the one thing in this shape that can say on its own whether the
# walk is still in step. The length is derived on write and never a column.
# That matters more here than for LPSTR: a length that disagreed with its
# string would not truncate that string, it would move every byte of the pool
# after it.
#
# It is a *field* kind and not a table kind because in the record it is an
# ordinary fixed 4 bytes at a fixed offset, inside a record whose size the
# table header states. PoolGrammar below is the other arrangement -- an array
# of lengths and a count of how many are used -- and neither reduces to the
# other: there a record has a *list* of strings, here a string is one field
# the record always has.
POOLSTR = "poolstrz"
POOLSTR_FORMAT = "<I"
POOLSTR_SIZE = struct.calcsize(POOLSTR_FORMAT)

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
    if ftype == POOLSTR:
        # Fixed, and that is the point of the kind: what the record holds is
        # the 4-byte length. The text it measures is in the table's pool.
        return POOLSTR_SIZE
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
    if ftype == POOLSTR:
        raise EdfError("%s: a pooled string is read by its table, which knows "
                       "where the pool starts -- not field by field" % where)
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
    if ftype == POOLSTR:
        raise EdfError("a pooled string is written by its table, which writes "
                       "the length here and the text in the pool -- not field "
                       "by field")
    return encode(value, ftype)


def parse_field(text, ftype):
    """Turn CSV text into a value `write_field` will accept, or raise."""
    m = _ZSTR_RE.match(ftype)
    if m or ftype in (LPSTR, WPSTR, POOLSTR):
        try:
            raw = text.encode("latin-1")
        except UnicodeEncodeError:
            raise ValueError("contains characters this file's encoding can't "
                             "store (latin-1 only; paste plain text)")
        if m and len(raw) > int(m.group(1)):
            raise ValueError("too long: %d bytes, field holds %s"
                             % (len(raw), m.group(1)))
        if ftype in (LPSTR, POOLSTR) and b"\x00" in raw:
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


# A **chain** grammar: BACKLOG #52's fourth shape, and the plainest of them
# -- an ordinary 8-byte chain-format table read with a hand-written field list
# instead of an inferred schema.
#
# The 17 chain files need no such thing: `parse_table_chain` walks them and
# `rf_dat` infers their schemas. But a file that is chain-shaped in *part* and
# something else after it cannot go through that walk at all, and its
# chain-shaped tables still have to be read. NDQuest.edf is that file: 262
# names in a chain table, then a chain table of records whose text is pooled
# behind them.
#
# The header states the record size, so this is the one grammar kind that can
# be checked against the file rather than merely fitting inside it: the
# fields have to add up to the number the file itself declares. A field may be
# POOLSTR, and then the table's pool follows its records.
ChainGrammar = collections.namedtuple("ChainGrammar", "fields")


def chain_record_size(grammar):
    """Bytes one record occupies -- what its table header must say."""
    return sum(field_width(t) for _, t in grammar.fields)


# An **inferred chain** table: BACKLOG #52's fifth shape, and the only one
# that adds no reading of its own. It is an ordinary 8-byte chain-format table
# -- `<u32 record_count><u32 record_size>` and fixed records -- sitting in a
# file that is not a chain end to end, read exactly the way the 17 chain files
# are, `infer_schema` and all.
#
# GameData.edf is why it exists. Its first eight tables *are* chain tables:
# the first seven are EventShip.edf's entire payload, table for table, and
# that file is one of the 17 that already round-trip byte-exactly. Only the
# ninth table is something else -- and one count-only table at the end is
# enough to stop `parse_table_chain` at offset 0, because the chain walk is
# all-or-nothing by design.
#
# So this is the one entry in EDF_TABLE_GRAMMARS that is not a hand-derived
# layout, for the good reason that there is nothing to derive: the header
# states the record size, `infer_schema` labels the fields as it does for
# every chain file, and the byte-exact round trip is the check, unchanged.
# Spelling those eight tables out as ChainGrammars instead would have replaced
# inference proven on 17 files with fifty-odd hand-typed field names, and
# asserted boundaries the file already states.
class _InferredChain(object):
    """The type of `INFERRED_CHAIN`; a class only so it can be recognised."""

    __slots__ = ()

    def __repr__(self):
        return "INFERRED_CHAIN"


INFERRED_CHAIN = _InferredChain()


def _parse_inferred_chain(data, offset, source):
    """Read one ordinary chain-format table at `offset`, schema inferred.

    Returns the `rf_dat.Table` and the offset just past it. Header checks are
    `chain_layout`'s, for `chain_layout`'s reason: a count or a record size
    outside these is a misread header rather than a table, and saying so beats
    allocating on a garbage length.
    """
    if offset + CHAIN_HEADER_SIZE > len(data):
        raise EdfError("%s: %d byte(s) left, too few for an 8-byte table "
                       "header" % (source, len(data) - offset))
    count, rec_size = struct.unpack_from(CHAIN_HEADER, data, offset)
    if rec_size == 0 or rec_size > MAX_RECORD_SIZE or count > MAX_RECORD_COUNT:
        raise EdfError("%s: reads as %d records of %d bytes, which is not a "
                       "table header" % (source, count, rec_size))
    start = offset + CHAIN_HEADER_SIZE
    end = start + count * rec_size
    if end > len(data):
        raise EdfError("%s: claims %d records of %d bytes, %d past the end of "
                       "the payload"
                       % (source, count, rec_size, end - len(data)))
    return _table_from_records(data[start:end], count, rec_size, source), end


# A **pool** grammar: BACKLOG #52's third shape, the one NDMsgMonster.edf is.
# The records are fixed-width and sit in an ordinary chain-format table,
# header and all -- but each carries an array of byte *lengths* whose text is
# not in the record. All the text lives in one pool after the table, in record
# order, and a record's slots say how long each of its strings is.
#
# So a record and its strings are two regions of the file rather than one run,
# which is why this cannot be a BlockGrammar: over there a block's items
# follow the block. `lead` is the fixed fields in front of the slot array,
# `slots` how many the array holds, and `count` the field after it saying how
# many are used. Slots past that count are zero, which the reader checks
# rather than assumes -- a nonzero one would mean the array is something else
# and the rest of the walk is wrong.
#
# `item` is a name, not a field list: the pooled string is the whole item and
# its length is the slot's, so there is nothing for a second field to be. It
# carries LPSTR's contract -- the slot counts a trailing NUL the CSV does not
# hold -- so, as everywhere else here, the length is derived on write and
# never a column anyone has to keep in step.
PoolGrammar = collections.namedtuple(
    "PoolGrammar", "lead slot_type slots count item")

# What a length slot or a used-slot count may be. Same reasoning as
# BLOCK_COUNT_TYPES: anything wider is not a length or a count, and reading
# one as the other would mean the shape was read wrong.
POOL_SLOT_TYPES = BLOCK_COUNT_TYPES


def pool_record_size(grammar):
    """Bytes one pooled record occupies -- what its table header must say."""
    return (sum(field_width(t) for _, t in grammar.lead)
            + grammar.slots * field_size(grammar.slot_type)
            + field_size(grammar.count))


# A **nest** grammar: BACKLOG #52's sixth shape, and the widest of them -- a
# block with *several* nested runs rather than one. Map.edf is why it exists.
# One of its map blocks carries four: the 288-byte spawn records, a parallel
# array of portal links, the placed objects only `resources` has, and the
# named passages -- and then 76 bytes of block-level fixed fields *after* all
# of them. BlockGrammar reaches exactly one run and has nothing after it, so
# stretching it would have meant making its single `item` list optional and
# repeatable on the settled path Hint.edf and UIHelp.edf depend on.
#
# `head` is the fields before the first run, `tail` the fields after the last
# (possibly empty), and `runs` the nested lists in file order. Each run says
# how its length is written, and none of the three ways is a CSV column --
# same reason BlockGrammar's count is not one. Getting a nested length wrong
# does not truncate one record, it moves every byte after it.
NestRun = collections.namedtuple("NestRun", "name count fields")
NestGrammar = collections.namedtuple("NestGrammar", "head runs tail")

# `count` may be:
#   one of BLOCK_COUNT_TYPES -- the run writes its own count in front of it;
#   SAME_COUNT               -- the run has no count of its own and is exactly
#                               as long as the run before it. Map.edf's link
#                               array is this: the file states one number and
#                               two arrays follow it, so a link belongs to the
#                               spawn record at the same index and there is
#                               nothing for a second count to be;
#   BYTE_LENGTH              -- the run writes a `<u32>` *byte* length rather
#                               than a record count. Map.edf's minimap cells
#                               are this. The records must then be fixed-width
#                               so the two convert, and the reader refuses a
#                               length that is not a whole number of them.
SAME_COUNT = "same"
BYTE_LENGTH = "bytes"
BYTE_LENGTH_FORMAT = "<I"
BYTE_LENGTH_SIZE = struct.calcsize(BYTE_LENGTH_FORMAT)


def nest_run_size(run):
    """Bytes one record of a BYTE_LENGTH run occupies."""
    return sum(field_width(t) for _, t in run.fields)


# A **group** grammar: BACKLOG #56's shape, and the only one in this layer
# whose lengths are not in its own payload at all. `en-ph/NDMap.edf` is why it
# exists. The file is `<u32 group_count>` and then every record of every
# group back to back, with nothing marking where one group ends -- those
# lengths are in `Map.edf`, whose blocks these groups stand one-for-one
# against. NDMap is the localized *name* table for Map's records, so being
# unreadable without it is a property of the format, not of this reader.
#
# The split is derived, not guessed. Over Map.edf's 37 map blocks
# `1 + records + passages` is exactly 599, the number of 64-byte names the
# region holds and the offset the run was already known to end at; in all 21
# blocks that have passages the last P names of the group are that block's
# passage names verbatim and in order, and each group opens with the map's
# display name (`NeutralB` -> `Bellato HQ`). The two minimap tables agree the
# same way: 202 labels over the 31 world grids and 43 over the 7 insets, one
# label per mark, `Cauldron01`'s 7 icons getting `Abandon Cave`,
# `Genial Spr.`, `Vapor Lake`, ...
#
# **The companion is read to parse, and never to rebuild.** The group each row
# belongs to travels in the CSV's `Block` column, exactly as a nested run's
# rows do, so `from_csv` needs nothing but its own CSV and an edit to `Map.edf`
# alone cannot move a byte of a rebuilt `NDMap.edf`. What such an edit *can*
# do is leave the `Block` column describing a grouping the client no longer
# uses -- a content mismatch between two files, which no byte layer can see.
#
# `CompanionRuns` says where a group length comes from: `plus`, plus the
# lengths of the named runs of block i of table `table` of file `file`.
CompanionRuns = collections.namedtuple("CompanionRuns", "file table runs plus")
GroupGrammar = collections.namedtuple("GroupGrammar", "groups fields")


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
    if grammar is INFERRED_CHAIN:
        # Nothing to check: the file states the record size and the schema is
        # inferred from the records, exactly as for a chain file.
        return grammar
    if isinstance(grammar, ChainGrammar):
        _verify_fields(grammar.fields, "%s record" % source)
        for name, ftype in grammar.fields:
            if field_width(ftype) is None:
                raise EdfError("%s: field %s is variable-width, and a "
                               "chain-format record is not -- its size is "
                               "stated in the table header" % (source, name))
        return grammar
    if isinstance(grammar, PoolGrammar):
        for what, ftype in (("slot", grammar.slot_type),
                            ("string count", grammar.count)):
            if ftype not in POOL_SLOT_TYPES:
                raise EdfError("%s: %r is not a %s type (%s)"
                               % (source, ftype, what,
                                  ", ".join(POOL_SLOT_TYPES)))
        if grammar.slots < 1:
            raise EdfError("%s: a record with %d length slot(s) has nowhere "
                           "to point at the pool" % (source, grammar.slots))
        _verify_fields(grammar.lead, "%s record" % source)
        for name, ftype in grammar.lead:
            if field_width(ftype) is None:
                raise EdfError("%s: field %s is variable-width, and a pooled "
                               "record is not -- its size is stated in the "
                               "table header" % (source, name))
        if grammar.item == BLOCK_COLUMN:
            raise EdfError("%s: the pooled string may not be called %r -- "
                           "that column carries the record number"
                           % (source, BLOCK_COLUMN))
        return grammar
    if isinstance(grammar, GroupGrammar):
        spec = grammar.groups
        if not isinstance(spec, CompanionRuns):
            raise EdfError("%s: a group grammar takes its lengths from a "
                           "CompanionRuns, not %r" % (source, spec))
        if not spec.file:
            raise EdfError("%s: a group grammar must name the file its group "
                           "lengths come from" % source)
        if spec.table < 0:
            raise EdfError("%s: %r is not a table index in %s"
                           % (source, spec.table, spec.file))
        if not spec.runs:
            raise EdfError("%s: a group grammar must name at least one run of "
                           "%s to measure a group by" % (source, spec.file))
        if spec.plus < 0:
            raise EdfError("%s: a group cannot be %d record(s) shorter than "
                           "the runs measuring it" % (source, spec.plus))
        _verify_fields(grammar.fields, "%s record" % source)
        if any(n == BLOCK_COLUMN for n, _ in grammar.fields):
            raise EdfError("%s: a field may not be called %r -- that column "
                           "carries the group number" % (source, BLOCK_COLUMN))
        return grammar
    if isinstance(grammar, NestGrammar):
        _verify_fields(grammar.head, "%s block header" % source)
        if not grammar.runs:
            raise EdfError("%s: a nested grammar with no runs is a flat one -- "
                           "use a plain field list" % source)
        seen = set()
        for pos, run in enumerate(grammar.runs):
            where = "%s run %s" % (source, run.name)
            if not run.name or run.name in seen:
                raise EdfError("%s: run name %r is missing or repeated -- each "
                               "run gets its own CSV beside the block one"
                               % (source, run.name))
            seen.add(run.name)
            if run.count == SAME_COUNT:
                if pos == 0:
                    raise EdfError("%s: the first run has no run before it to "
                                   "take its length from" % where)
            elif run.count == BYTE_LENGTH:
                for name, ftype in run.fields:
                    if field_width(ftype) is None:
                        raise EdfError(
                            "%s: field %s is variable-width, and a run measured "
                            "in bytes cannot say how many records that is"
                            % (where, name))
            elif run.count not in BLOCK_COUNT_TYPES:
                raise EdfError("%s: %r is not a record-count type (%s, %s, %s)"
                               % (where, run.count, ", ".join(BLOCK_COUNT_TYPES),
                                  SAME_COUNT, BYTE_LENGTH))
            _verify_fields(run.fields, where)
            if any(n == BLOCK_COLUMN for n, _ in run.fields):
                raise EdfError("%s: a field may not be called %r -- that column "
                               "carries the block number" % (where, BLOCK_COLUMN))
        if grammar.tail:
            _verify_fields(grammar.head + grammar.tail,
                           "%s block header and trailer" % source)
        return grammar
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
    # BACKLOG #52. The pooled shape, and the only file so far that is one: a
    # chain-format table of 373 fixed 88-byte records -- `<i32 id>`, twenty
    # `<u32>` length slots and a `<u32>` count of how many are used -- and
    # then, after the table, every record's message text in one pool, in
    # record order.
    #
    # **What makes this a derivation and not a guess is that the record table
    # states each string's length separately, and all 1098 agree.** The pool
    # holds 1098 NUL-terminated strings; the record counts sum to exactly
    # 1098 across the 373 records; and for every one of those strings the
    # slot's value is its length with the terminator counted. A boundary
    # wrong anywhere would put one of the 1098 agreements out, and none is
    # out. The record run is pinned twice over besides -- `Id` runs 0..372,
    # matching the 373 the header declares, and the header's own 88-byte
    # record size is exactly what these fields add up to, which the reader
    # checks rather than assumes.
    #
    # Every slot at or past a record's count is zero, checked in all 373, so
    # the twenty are one array and not three lengths plus seventeen other
    # fields: 88 bytes is `int id; int len[20]; int count;`. Records 0-6 are
    # the seven that use none of it, all fields zero. Which of a monster's
    # three messages is which the file does not say, so they keep file order
    # and no names.
    "ndmsgmonster.edf": [
        PoolGrammar(lead=[("Id", "dword")], slot_type="udword", slots=20,
                    count="udword", item="Text"),
    ],
    # BACKLOG #52. Two chain-format tables and one pool: 262 x 32 NUL-padded
    # quest-item names, then 4176 x 16-byte records whose text is not in them,
    # then those 4176 strings end to end, ending exactly on the last of 645282
    # payload bytes.
    #
    # **What makes this a derivation and not a guess is that the file states
    # each string's length separately, and all 4176 agree.** Every record's
    # third dword is exactly its string's length with the terminator counted,
    # for all 4176 -- one boundary wrong anywhere would put one of those 4176
    # agreements out. `Id` runs 0..4175 independently of that, matching the
    # 4176 the header declares, and both tables' 8-byte headers state a record
    # size the grammar has to add up to, which ChainTable checks rather than
    # assumes: 32 and 16.
    #
    # The two zero dwords are numbered rather than named. They are zero in all
    # 4176 records, which is exactly as consistent with padding as with fields
    # nothing in this file ever sets -- and the same `<u32 id><u32 0><u32 len>`
    # prefix opens NDItem.edf's 45 description tables, where the text is
    # inline instead of pooled. Two files spelling the same three fields the
    # same way is worth more than either reading of the spare.
    #
    # What the names in the first table are *for* the file does not say: 262
    # of them against 4176 strings is not a per-quest pairing, and nothing
    # here indexes one into the other. They keep file order and no role.
    "ndquest.edf": [
        ChainGrammar([("Name", "zstr[32]")]),
        ChainGrammar([("Id", "dword"), ("Unknown1", "dword"),
                      ("Text", POOLSTR), ("Unknown2", "dword")]),
    ],
    # BACKLOG #52. The first *mixed* file: eight ordinary chain tables and
    # then one that is not a chain table at all.
    #
    # **What makes the eight a reading rather than a guess is that another
    # file already is them.** EventShip.edf's whole payload is a chain of
    # 198x8, 5x80, 5x80, 6x80, 768x16, 768x16, 864x16 -- exactly this file's
    # first seven tables, in that order, and 1109 bytes apart in content out
    # of 41320. EventShip.edf is one of the 17 that already round-trip
    # byte-exactly, so those seven tables need no new reading and get none;
    # the eighth, 11x8, is a chain table by the same header. See
    # INFERRED_CHAIN above for why they are not hand-written field lists.
    #
    # The ninth table is `<u32 61>` and then 61 x
    # (`<u32 len><len bytes><i32 -1>`): the flying-ship announcements. The
    # chain walk mistook that count and the first message's length for a
    # table header -- "61 records of 155 bytes", 155 being the length of
    # `Kartella is happy to serve you!...` -- which is why it did not break
    # here but 9463 bytes further on, mid-word, in the middle of a sentence.
    #
    # **What makes the ninth a derivation is NDEventShip.edf.** That file is
    # this one's localisation pair -- the same 5, 5, 6 and 11 entries in
    # narrower records -- and carries the same table. Walked independently,
    # from an offset 40140 bytes away, it closes on its own last payload byte
    # with 61 records too, and 60 of its 61 messages are byte-identical to
    # these. The one that is not, record 58, differs only in the right single
    # quote: cp1252 `92` here, UTF-8 `e2 80 99` there, which is the whole of
    # the two records' 2-byte length difference. Sixty-one agreements between
    # two walks that share no offset, on top of the 61 the file itself
    # declares matching the 61 the walk reads.
    #
    # Every message is one NUL-terminated run inside its length, which LPSTR
    # checks record by record and all 122 pass. The trailing dword is
    # numbered rather than named: it is -1 in every record of both files, and
    # a constant says nothing about its own role -- an unused index and a
    # "none" sentinel look identical from here.
    "gamedata.edf": [INFERRED_CHAIN] * 8 + [
        [("Text", LPSTR), ("Unknown1", "dword")],
    ],
    # BACKLOG #52. GameData.edf's localisation pair, and the other half of
    # that entry's cross-check -- read it there. Four chain tables (5, 5 and
    # 6 port names in 64-byte records, then 11 x 20) and the same 61
    # announcements, in the same order, in the same shape.
    "ndeventship.edf": [INFERRED_CHAIN] * 4 + [
        [("Text", LPSTR), ("Unknown1", "dword")],
    ],
    # BACKLOG #52. The client's asset manifest: 27 count-only tables of
    # fixed-width records, three shapes repeating nine times, closing exactly
    # on the last of 7 679 792 payload bytes. It needs no new machinery -- the
    # records are flat fixed fields -- so all the work here was the record
    # sizes, which the file does not state.
    #
    # **What derives them is that the tables say what they hold.** Each record
    # carries a 128-byte directory and a 64-byte file name, and the three
    # shapes are the three halves of one asset: a skeleton (`.BN`) with its
    # bounding box (`.BBX`), a mesh (`.MSH`) with the directory of its
    # textures, and an animation (`.ANI`). Read at these sizes, all 28 011
    # records agree, with no exceptions anywhere:
    #
    #   * every one of the 1 205 bone records has a `.BN` at +132 and a
    #     `.BBX` at +196; every one of the 9 830 mesh records a `.MSH` at
    #     +136; every one of the 16 976 animation records an `.ANI` at +136;
    #   * every record's text begins exactly at the field offsets below, and
    #     not one record of the 28 011 has a byte after a terminator inside a
    #     slot -- a boundary off by any amount would put a name's tail in the
    #     next field in some record somewhere;
    #   * the 48 distinct directory values are real client asset directories
    #     (`.\CHARACTER\PLAYER\BONE\`, `.\ITEM\WEAPON\MESH\`, ...), 42 of
    #     which exist in the AoP 4.15 install, and where a directory's assets
    #     are unpacked on disk rather than in the client's archive its names
    #     resolve to real files -- player bone 10 of 10, animus bone 80 of 80,
    #     guard tower bone 22 of 22, armour animation 160 of 160.
    #
    # The nine groups are asset families -- PLAYER, MONSTER, ANIMUS,
    # GUARDTOWER, NPC, ITEM, UNIT and two more of player animations -- and
    # each group's three tables are that family's `BONE\`, `MESH\`+`TEX\` and
    # `ANI\` directories. That a fixed three-table cycle falls out nine times
    # over, each time on one family, is the cross-check: a record size wrong
    # anywhere in the walk would land the next table's count on bytes that are
    # not a count, and could not put the right directory in the right table
    # twenty-seven times running. `Id` corroborates it again -- within a group
    # the bone and mesh tables key on the same id space (monsters 0..552 in
    # both, guard towers 16 424..41 256 in both, NPCs 12 288..169 135 in both)
    # while being read at different record sizes.
    #
    # Everything not a path or a name is numbered rather than named. The
    # animation record's ten trailing dwords are an array with its used count
    # in front, but the count stays an ordinary column and is not derived from
    # the values: 181 of the 16 976 records have a count of 1 over an array
    # whose first entry is 0, so a zero entry is a value here and not an empty
    # slot, and rebuilding the count from the array would corrupt them.
    "resource.edf": [
        # a skeleton and its bounding box
        [("Id", "dword"), ("Path", "zstr[128]"),
         ("BoneFile", "zstr[64]"), ("BoundsFile", "zstr[64]")],
        # a mesh, and the directory its textures live in
        [("Id", "dword"), ("Unknown1", "dword"), ("MeshPath", "zstr[128]"),
         ("MeshFile", "zstr[64]"), ("TexPath", "zstr[128]")],
        # an animation, and ten numbers with a count in front of them
        [("Id", "dword"), ("Unknown1", "dword"), ("Path", "zstr[128]"),
         ("AniFile", "zstr[64]"), ("Unknown2", "dword")]
        + [("Unknown%d" % (i + 3), "dword") for i in range(10)],
    ] * 9,
    # BACKLOG #52, seventh session. Three tables: the 37 map blocks, then the
    # 31 world minimaps, then the 7 world-map insets. The blocks were already
    # found (each opens with its own index, 0..36 in file order) and their
    # 298-byte header read; what this session derived is everything after it.
    #
    # A block's `count` covers *two* runs -- the 288-byte spawn/portal records
    # and, after all of them, one dword pair per record. The pair is a link:
    # 219 of the 436 are not (-1, -1), and every one of those 219 names a real
    # (map index, record index) in this same file, which is what says the two
    # arrays are parallel rather than one array of some other length.
    #
    # Three things inside the 288-byte record agree with numbers only the walk
    # knows: field 1 is the owning block's index in all 436 records, field 2 is
    # the record's index inside its block in all 436, and the 16 floats at +32
    # have 0, 0, 0, 1.0 in the places a 4x4 affine transform's last column
    # holds them -- so the bounding box and matrix are read, not guessed at.
    # The 96-byte `areas` run is the same geometry without the name or the
    # flags, and only `resources` has any (226 of them; the other 36 blocks
    # write a zero count).
    #
    # A minimap's cells are `<u32 byte length>` then `<u16 repeat><u8 value>`
    # triplets, a run being `repeat + 1` cells long. Across all 38 grids the
    # cells add up to exactly `Width * Height` -- 26 283 runs agreeing with a
    # number the record states separately, which is what proves the triplet.
    "map.edf": [
        NestGrammar(
            [("Id", "dword"), ("Name", "zstr[32]"), ("BspPath", "zstr[128]"),
             ("SprFile", "zstr[128]"), ("Unknown1", "uword")],
            [
                # the spawn and portal entries: `dpgoto_bellato_HQ`,
                # `dpfrom_bl_grsd`, each with a world bounding box and a
                # placement matrix
                NestRun("records", "udword",
                        [("MapIndex", "dword"), ("Index", "dword"),
                         ("MinX", "float"), ("MinY", "float"),
                         ("MinZ", "float"), ("MaxX", "float"),
                         ("MaxY", "float"), ("MaxZ", "float")]
                        + [("M%d%d" % (r, c), "float")
                           for r in range(4) for c in range(4)]
                        + [("Unknown1", "dword"), ("Unknown2", "dword"),
                           ("Unknown3", "dword"), ("Unknown4", "ubyte"),
                           ("Name", "zstr[128]"), ("Unknown5", "ubyte"),
                           ("Unknown6", "ubyte"), ("Unknown7", "ubyte")]
                        + [("Unknown%d" % (i + 8), "dword")
                           for i in range(12)]),
                # where each of those records leads, or (-1, -1) for nowhere
                NestRun("links", SAME_COUNT,
                        [("ToMap", "dword"), ("ToRecord", "dword")]),
                # placed objects: a bounding box and a transform, no name
                NestRun("areas", "udword",
                        [("Unknown1", "dword"), ("Unknown2", "dword"),
                         ("MinX", "float"), ("MinY", "float"),
                         ("MinZ", "float"), ("MaxX", "float"),
                         ("MaxY", "float"), ("MaxZ", "float")]
                        + [("M%d%d" % (r, c), "float")
                           for r in range(4) for c in range(4)]),
                # the named passages: `Road to Beast Mountain`. `Index` is not
                # per block -- it runs 0..125 across the whole file.
                NestRun("passages", "udword",
                        [("Index", "dword"), ("Unknown1", "dword"),
                         ("Unknown2", "dword"), ("Unknown3", "dword"),
                         ("Unknown4", "dword"), ("Name", "zstr[64]")]),
            ],
            # 19 dwords after the last run. Unknown15 and Unknown16 are N and
            # N - 1 in all 37 blocks, whatever N counts.
            [("Unknown2", "float")]
            + [("Unknown%d" % (i + 3), "dword") for i in range(4)]
            + [("Unknown7", "float")]
            + [("Unknown%d" % (i + 8), "dword") for i in range(13)]),
    ] + [
        NestGrammar(
            [("Width", "dword"), ("Height", "dword"), ("Name", LPSTR)],
            [
                # icons on the minimap. All 245 land inside their own grid
                # read this way round and 19 do not read the other way, which
                # is what names Y and X and nothing else here.
                NestRun("marks", "udword",
                        [("Unknown1", "dword"), ("Y", "dword"),
                         ("X", "dword"), ("Unknown2", "dword")]),
                # one run of `Repeat + 1` cells of `Value`
                NestRun("cells", BYTE_LENGTH,
                        [("Repeat", "uword"), ("Value", "ubyte")]),
            ],
            []),
    ] * 2,
    # BACKLOG #56. `Map.edf`'s names, localized -- three tables that mirror
    # `Map.edf`'s three one for one, and the only file in this layer that
    # states none of its own record counts. See the GroupGrammar note above
    # for the agreements that fix the split, and
    # docs/knowledge/edf-payload-tables.md for the full reading.
    #
    # A block's names are its display name, then one per record of the map --
    # `dpgoto_bellato_HQ` -> `Bellato HQ`, with `0` where a record has no
    # label -- then one per passage, verbatim. The two minimap tables are one
    # label per mark, in mark order.
    "ndmap.edf": [
        GroupGrammar(CompanionRuns("Map.edf", 0, ("records", "passages"), 1),
                     [("Name", "zstr[64]")]),
    ] + [
        GroupGrammar(CompanionRuns("Map.edf", 1, ("marks",), 0),
                     [("Label", LPSTR)]),
        GroupGrammar(CompanionRuns("Map.edf", 2, ("marks",), 0),
                     [("Label", LPSTR)]),
    ],
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


def _items_path(path):
    """Where a two-region table's item rows live, given its main CSV path."""
    base, ext = os.path.splitext(path)
    return base + ".items" + (ext or ".csv")


def _group_items(leads, items, nrows, path, ipath):
    """Bucket item rows by their `Block` column, keeping them in file order.

    Item order inside a block is byte order, so the rows are written back in
    the order they are read: they must stay grouped and in block order, and
    saying so is better than quietly reshuffling the payload.
    """
    where = os.path.basename(ipath)
    groups = [[] for _ in range(nrows)]
    last = -1
    for i, (block, item) in enumerate(zip(leads, items)):
        if not 0 <= block < nrows:
            raise ValueError("%s line %d: block %d, but %s has %d block(s)"
                             % (where, i + 2, block,
                                os.path.basename(path), nrows))
        if block < last:
            raise ValueError(
                "%s line %d: block %d after block %d -- item rows are "
                "written back in the order they appear, so they must stay "
                "grouped and in block order" % (where, i + 2, block, last))
        last = block
        groups[block].append(item)
    return groups


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
        return _items_path(path)

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
        self.rows = rows
        self.items = _group_items(leads, items, len(rows), path, ipath)
        return rows


class PoolTable(object):
    """A chain-format table whose strings live in a pool after the records.

    `<u32 record_count><u32 record_size>`, then the fixed records, then every
    record's strings end to end -- record order, and slot order inside a
    record. Two regions, so two CSVs, joined by the same `Block` column
    BlockTable uses; here a block is a record.

    The record size in the header is not taken on trust: it has to equal what
    the grammar's own fields add up to. That is a check the count-only formats
    cannot make at all -- this shape states its record size, so a grammar that
    disagrees with it is wrong about the file, not about a labelling detail.
    """

    def __init__(self, grammar, rows, items, source=None, grammar_source=None):
        self.grammar = verify_grammar(grammar, source or "grammar")
        if len(rows) != len(items):
            raise EdfError("%s: %d record(s) but %d string list(s)"
                           % (source or "table", len(rows), len(items)))
        self.rows = rows
        self.items = items
        self.source = source
        self.grammar_source = grammar_source

    @staticmethod
    def items_path(path):
        """Where the string rows live, given the record CSV's path."""
        return _items_path(path)

    def _item_fields(self):
        """The strings CSV's grammar.

        LPSTR, because the contract is LPSTR's exactly -- text with a
        terminator counted in a length that is derived, never typed. The only
        difference is where that length is written, and the CSV does not hold
        it either way.
        """
        return [(self.grammar.item, LPSTR)]

    @classmethod
    def parse(cls, data, offset, grammar, source):
        """Read the table at `offset` and the string pool after it.

        Returns the table and the offset just past the pool.
        """
        verify_grammar(grammar, source)
        if offset + CHAIN_HEADER_SIZE > len(data):
            raise EdfError("%s: %d byte(s) left, too few for an 8-byte table "
                           "header" % (source, len(data) - offset))
        count, rec_size = struct.unpack_from(CHAIN_HEADER, data, offset)
        pos = offset + CHAIN_HEADER_SIZE
        if count > MAX_RECORD_COUNT:
            raise EdfError("%s: reads as %d records, which is not a record "
                           "count" % (source, count))
        want = pool_record_size(grammar)
        if rec_size != want:
            raise EdfError("%s: the header says %d-byte records and the "
                           "grammar describes %d -- the grammar does not fit "
                           "this file" % (source, rec_size, want))
        rows, lengths = [], []
        for i in range(count):
            row = {}
            for name, ftype in grammar.lead:
                row[name], pos = read_field(
                    data, pos, ftype,
                    "%s record %d field %s" % (source, i, name))
            slots = []
            for k in range(grammar.slots):
                value, pos = read_field(
                    data, pos, grammar.slot_type,
                    "%s record %d length slot %d" % (source, i, k))
                slots.append(value)
            n, pos = read_field(data, pos, grammar.count,
                                "%s record %d string count" % (source, i))
            if n > grammar.slots:
                raise EdfError("%s record %d: reads as %d string(s), more "
                               "than the %d slot(s) the record holds"
                               % (source, i, n, grammar.slots))
            spare = [k for k in range(n, grammar.slots) if slots[k]]
            if spare:
                raise EdfError("%s record %d: it uses %d of its %d slot(s), "
                               "but unused slot %d holds %d rather than zero "
                               "-- these are not lengths, and the rest of the "
                               "walk is wrong"
                               % (source, i, n, grammar.slots, spare[0],
                                  slots[spare[0]]))
            rows.append(row)
            lengths.append(slots[:n])
        items = []
        for i, lens in enumerate(lengths):
            group = []
            for k, length in enumerate(lens):
                where = "%s record %d string %d" % (source, i, k)
                if length < 1:
                    raise EdfError("%s: its slot says %d bytes, too few for "
                                   "even a terminator" % (where, length))
                if pos + length > len(data):
                    raise EdfError("%s: its slot says %d bytes, %d past the "
                                   "end of the payload"
                                   % (where, length, pos + length - len(data)))
                blob = data[pos:pos + length]
                # The same contract LPSTR reads, and it does the same work: a
                # pooled string is the one thing here that can say on its own
                # whether the walk is still in step.
                if not blob.endswith(b"\x00") or b"\x00" in blob[:-1]:
                    raise EdfError(
                        "%s: the %d bytes its slot points at are not one "
                        "NUL-terminated run (%r) -- the grammar does not fit "
                        "this file" % (where, length, blob[:32]))
                group.append({grammar.item: blob[:-1].decode("latin-1")})
                pos += length
            items.append(group)
        return cls(grammar, rows, items, source=source,
                   grammar_source="hand-derived (EDF_TABLE_GRAMMARS)"), pos

    def to_bytes(self):
        where = self.source or "table"
        g = self.grammar
        out = bytearray(struct.pack(CHAIN_HEADER, len(self.rows),
                                    pool_record_size(g)))
        pool = bytearray()
        for i, (row, group) in enumerate(zip(self.rows, self.items)):
            if len(group) > g.slots:
                raise EdfError("%s record %d: %d string(s), more than the %d "
                               "slot(s) the record holds"
                               % (where, i, len(group), g.slots))
            for name, ftype in g.lead:
                try:
                    out += write_field(row[name], ftype)
                except ValueError as exc:
                    raise EdfError("%s record %d field %s: %s"
                                   % (where, i, name, exc))
            raws = []
            for j, item in enumerate(group):
                try:
                    raw = str(item[g.item]).encode("latin-1")
                except ValueError:
                    raise EdfError("%s record %d string %d: contains "
                                   "characters this file's encoding can't "
                                   "store (latin-1 only)" % (where, i, j))
                if b"\x00" in raw:
                    raise EdfError("%s record %d string %d: must not contain "
                                   "a NUL byte -- the terminator is written "
                                   "for you" % (where, i, j))
                raws.append(raw)
            # The lengths are written from the strings, never carried: a slot
            # disagreeing with its string would not truncate that string, it
            # would move every byte of the pool after it.
            for k in range(g.slots):
                length = len(raws[k]) + 1 if k < len(raws) else 0
                try:
                    out += write_field(length, g.slot_type)
                except (ValueError, struct.error):
                    raise EdfError("%s record %d string %d: %d bytes is more "
                                   "than this file's %s length slot can hold"
                                   % (where, i, k, length, g.slot_type))
            try:
                out += write_field(len(group), g.count)
            except (ValueError, struct.error):
                raise EdfError("%s record %d: %d string(s) is more than this "
                               "file's %s count can hold"
                               % (where, i, len(group), g.count))
            for raw in raws:
                pool += raw + b"\x00"
        return bytes(out + pool)

    @classmethod
    def from_csv(cls, csv_path, grammar):
        t = cls(grammar, [], [], source=os.path.basename(csv_path),
                grammar_source=os.path.basename(csv_path))
        t.import_csv(csv_path)
        return t

    def export_csv(self, path):
        names = [n for n, _ in self.grammar.lead]
        _write_csv(path, names,
                   ([escape_text(str(row[n])) for n in names]
                    for row in self.rows))
        item = self.grammar.item
        _write_csv(self.items_path(path), [BLOCK_COLUMN, item],
                   ([str(i), escape_text(str(row[item]))]
                    for i, group in enumerate(self.items) for row in group))

    def import_csv(self, path):
        _leads, rows = _read_csv(path, self.grammar.lead)
        ipath = self.items_path(path)
        leads, items = _read_csv(ipath, self._item_fields(), lead=BLOCK_COLUMN)
        self.rows = rows
        self.items = _group_items(leads, items, len(rows), path, ipath)
        return rows


class ChainTable(object):
    """A chain-format table read with a hand-written grammar.

    `<u32 record_count><u32 record_size>`, then the fixed records, then -- if
    any field is POOLSTR -- those fields' strings in one pool after them, in
    record order and field order inside a record.

    One CSV, not two. A pooled string here is one field of one record, so it
    is one column, and the invariant the whole layer rests on holds unchanged:
    one row per record, columns in record order. PoolTable needs a second file
    only because over there a record has a *list* of strings, and a list does
    not fit in a column.

    Deliberately not an `rf_dat.Table` subclass, for VarTable's reason and one
    more: Table computes its record size from the schema and writes the
    record's own bytes, and a pooled field's bytes are not in the record it is
    a field of.
    """

    def __init__(self, grammar, rows, source=None, grammar_source=None):
        self.grammar = verify_grammar(grammar, source or "grammar")
        self.rows = rows
        self.source = source
        self.grammar_source = grammar_source

    @classmethod
    def parse(cls, data, offset, grammar, source):
        """Read the table at `offset`, and its pool if it has one.

        Returns the table and the offset just past everything it owns.
        """
        verify_grammar(grammar, source)
        if offset + CHAIN_HEADER_SIZE > len(data):
            raise EdfError("%s: %d byte(s) left, too few for an 8-byte table "
                           "header" % (source, len(data) - offset))
        count, rec_size = struct.unpack_from(CHAIN_HEADER, data, offset)
        pos = offset + CHAIN_HEADER_SIZE
        if count > MAX_RECORD_COUNT:
            raise EdfError("%s: reads as %d records, which is not a record "
                           "count" % (source, count))
        want = chain_record_size(grammar)
        if rec_size != want:
            raise EdfError("%s: the header says %d-byte records and the "
                           "grammar describes %d -- the grammar does not fit "
                           "this file" % (source, rec_size, want))
        rows, pooled = [], []
        for i in range(count):
            row, lens = {}, []
            for name, ftype in grammar.fields:
                if ftype == POOLSTR:
                    if pos + POOLSTR_SIZE > len(data):
                        raise EdfError("%s record %d field %s: no room for "
                                       "the 4-byte pooled length"
                                       % (source, i, name))
                    lens.append(
                        (name,
                         struct.unpack_from(POOLSTR_FORMAT, data, pos)[0]))
                    pos += POOLSTR_SIZE
                    continue
                row[name], pos = read_field(
                    data, pos, ftype,
                    "%s record %d field %s" % (source, i, name))
            rows.append(row)
            pooled.append(lens)
        # The pool: every record's strings end to end, in record order, and in
        # field order inside a record. Nothing separates them but the lengths
        # already read, so this walk is the claim the grammar is making.
        for i, lens in enumerate(pooled):
            for name, length in lens:
                where = "%s record %d field %s" % (source, i, name)
                if length < 1:
                    raise EdfError("%s: its length says %d bytes, too few for "
                                   "even a terminator" % (where, length))
                if pos + length > len(data):
                    raise EdfError("%s: its length says %d bytes, %d past the "
                                   "end of the payload"
                                   % (where, length, pos + length - len(data)))
                blob = data[pos:pos + length]
                # LPSTR's contract, and it does LPSTR's work: a pooled string
                # is the one thing here that can say on its own whether the
                # walk is still in step.
                if not blob.endswith(b"\x00") or b"\x00" in blob[:-1]:
                    raise EdfError(
                        "%s: the %d bytes its length points at are not one "
                        "NUL-terminated run (%r) -- the grammar does not fit "
                        "this file" % (where, length, blob[:32]))
                rows[i][name] = blob[:-1].decode("latin-1")
                pos += length
        return cls(grammar, rows, source=source,
                   grammar_source="hand-derived (EDF_TABLE_GRAMMARS)"), pos

    def to_bytes(self):
        where = self.source or "table"
        out = bytearray(struct.pack(CHAIN_HEADER, len(self.rows),
                                    chain_record_size(self.grammar)))
        pool = bytearray()
        for i, row in enumerate(self.rows):
            for name, ftype in self.grammar.fields:
                if ftype != POOLSTR:
                    try:
                        out += write_field(row[name], ftype)
                    except ValueError as exc:
                        raise EdfError("%s record %d field %s: %s"
                                       % (where, i, name, exc))
                    continue
                try:
                    raw = str(row[name]).encode("latin-1")
                except UnicodeEncodeError:
                    raise EdfError("%s record %d field %s: contains characters "
                                   "this file's encoding can't store (latin-1 "
                                   "only; paste plain text)"
                                   % (where, i, name))
                if b"\x00" in raw:
                    raise EdfError("%s record %d field %s: must not contain a "
                                   "NUL byte -- the terminator is written for "
                                   "you" % (where, i, name))
                # Derived, never carried: a length disagreeing with its string
                # would not truncate that string, it would move every byte of
                # the pool after it.
                try:
                    out += struct.pack(POOLSTR_FORMAT, len(raw) + 1)
                except struct.error:
                    raise EdfError("%s record %d field %s: %d bytes is more "
                                   "than a 4-byte pooled length can hold"
                                   % (where, i, name, len(raw) + 1))
                pool += raw + b"\x00"
        return bytes(out + pool)

    @classmethod
    def from_csv(cls, csv_path, grammar):
        t = cls(grammar, [], source=os.path.basename(csv_path),
                grammar_source=os.path.basename(csv_path))
        t.import_csv(csv_path)
        return t

    def export_csv(self, path):
        names = [n for n, _ in self.grammar.fields]
        _write_csv(path, names,
                   ([escape_text(str(row[n])) for n in names]
                    for row in self.rows))

    def import_csv(self, path):
        _leads, rows = _read_csv(path, self.grammar.fields)
        self.rows = rows
        return rows


class NestTable(object):
    """One count-only table whose blocks nest several counted runs.

    `<u32 block_count>`, then per block the head fields, each run in file
    order with whatever length it declares, and last the tail fields. One CSV
    per level, as BlockTable does: the blocks in the file the caller names,
    and each run beside it as `<name>.<run>.csv`, joined by the same `Block`
    column. A block's head and tail fields share the block CSV -- they are one
    row's worth of facts even though bytes sit between them in the file.

    Run order inside a block is byte order, so each run's CSV is read back in
    the order it was written: rows must stay grouped and in block order, and
    the importer says so rather than quietly reshuffling the payload.
    """

    def __init__(self, grammar, rows, runs, source=None, grammar_source=None):
        self.grammar = verify_grammar(grammar, source or "grammar")
        if len(runs) != len(grammar.runs):
            raise EdfError("%s: %d run(s) of rows for a grammar with %d"
                           % (source or "table", len(runs), len(grammar.runs)))
        for run, groups in zip(grammar.runs, runs):
            if len(groups) != len(rows):
                raise EdfError("%s: %d block(s) but %d %s list(s)"
                               % (source or "table", len(rows), len(groups),
                                  run.name))
        self.rows = rows
        self.runs = runs
        self.source = source
        self.grammar_source = grammar_source

    @staticmethod
    def run_path(path, run_name):
        """Where one run's rows live, given the block CSV's path."""
        base, ext = os.path.splitext(path)
        return base + "." + run_name + (ext or ".csv")

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
        rows = []
        runs = [[] for _ in grammar.runs]
        for i in range(count):
            row = {}
            for name, ftype in grammar.head:
                row[name], pos = read_field(
                    data, pos, ftype,
                    "%s block %d field %s" % (source, i, name))
            previous = None
            for r, run in enumerate(grammar.runs):
                where = "%s block %d run %s" % (source, i, run.name)
                if run.count == SAME_COUNT:
                    n = previous
                elif run.count == BYTE_LENGTH:
                    if pos + BYTE_LENGTH_SIZE > len(data):
                        raise EdfError("%s: no room for the 4-byte length"
                                       % where)
                    length = struct.unpack_from(
                        BYTE_LENGTH_FORMAT, data, pos)[0]
                    pos += BYTE_LENGTH_SIZE
                    size = nest_run_size(run)
                    if length % size:
                        raise EdfError(
                            "%s: %d bytes is not a whole number of %d-byte "
                            "records -- the length was read at the wrong "
                            "offset" % (where, length, size))
                    n = length // size
                else:
                    n, pos = read_field(data, pos, run.count,
                                        "%s record count" % where)
                if n < 0 or n > MAX_RECORD_COUNT:
                    raise EdfError("%s: reads as %d records, which is not a "
                                   "record count" % (where, n))
                group = []
                for j in range(n):
                    item = {}
                    for name, ftype in run.fields:
                        item[name], pos = read_field(
                            data, pos, ftype,
                            "%s record %d field %s" % (where, j, name))
                    group.append(item)
                runs[r].append(group)
                previous = n
            for name, ftype in grammar.tail:
                row[name], pos = read_field(
                    data, pos, ftype,
                    "%s block %d field %s" % (source, i, name))
            rows.append(row)
        return cls(grammar, rows, runs, source=source,
                   grammar_source="hand-derived (EDF_TABLE_GRAMMARS)"), pos

    def to_bytes(self):
        where = self.source or "table"
        out = bytearray(struct.pack(COUNT_HEADER, len(self.rows)))
        for i, row in enumerate(self.rows):
            for name, ftype in self.grammar.head:
                try:
                    out += write_field(row[name], ftype)
                except ValueError as exc:
                    raise EdfError("%s block %d field %s: %s"
                                   % (where, i, name, exc))
            previous = None
            for r, run in enumerate(self.grammar.runs):
                group = self.runs[r][i]
                if run.count == SAME_COUNT:
                    if len(group) != previous:
                        raise EdfError(
                            "%s block %d: %d %s row(s) but %d in the run "
                            "before it -- the file states one count for both, "
                            "so they must have the same number of rows"
                            % (where, i, len(group), run.name, previous))
                elif run.count == BYTE_LENGTH:
                    out += struct.pack(BYTE_LENGTH_FORMAT,
                                       len(group) * nest_run_size(run))
                else:
                    try:
                        out += write_field(len(group), run.count)
                    except (ValueError, struct.error):
                        raise EdfError(
                            "%s block %d: %d %s row(s) is more than this "
                            "file's %s count can hold"
                            % (where, i, len(group), run.name, run.count))
                for j, item in enumerate(group):
                    for name, ftype in run.fields:
                        try:
                            out += write_field(item[name], ftype)
                        except ValueError as exc:
                            raise EdfError(
                                "%s block %d run %s record %d field %s: %s"
                                % (where, i, run.name, j, name, exc))
                previous = len(group)
            for name, ftype in self.grammar.tail:
                try:
                    out += write_field(row[name], ftype)
                except ValueError as exc:
                    raise EdfError("%s block %d field %s: %s"
                                   % (where, i, name, exc))
        return bytes(out)

    @classmethod
    def from_csv(cls, csv_path, grammar):
        t = cls(grammar, [], [[] for _ in grammar.runs],
                source=os.path.basename(csv_path),
                grammar_source=os.path.basename(csv_path))
        t.import_csv(csv_path)
        return t

    def export_csv(self, path):
        names = [n for n, _ in self.grammar.head + self.grammar.tail]
        _write_csv(path, names,
                   ([escape_text(str(row[n])) for n in names]
                    for row in self.rows))
        for run, groups in zip(self.grammar.runs, self.runs):
            inames = [n for n, _ in run.fields]
            _write_csv(self.run_path(path, run.name), [BLOCK_COLUMN] + inames,
                       ([str(i)] + [escape_text(str(item[n])) for n in inames]
                        for i, group in enumerate(groups) for item in group))

    def import_csv(self, path):
        _leads, rows = _read_csv(path, self.grammar.head + self.grammar.tail)
        runs = []
        for run in self.grammar.runs:
            rpath = self.run_path(path, run.name)
            leads, items = _read_csv(rpath, run.fields, lead=BLOCK_COLUMN)
            runs.append(_group_items(leads, items, len(rows), path, rpath))
        self.rows = rows
        self.runs = runs
        return rows


class GroupTable(object):
    """One count-only table whose groups are as long as another file says.

    `<u32 group_count>` and then every record of every group back to back,
    with nothing between them. One CSV, joined to the companion by the same
    `Block` column a nested run uses: row order is byte order, so the rows
    must stay grouped and in group order, and the importer says so rather
    than quietly reshuffling the payload.

    The count in front is the number of *groups*, not of records, and it is
    the only length this file states. `to_bytes` takes it from the rows, so
    the companion is read to parse the payload and never to rebuild it.
    """

    def __init__(self, grammar, rows, groups, source=None, grammar_source=None):
        self.grammar = verify_grammar(grammar, source or "grammar")
        if sum(groups) != len(rows):
            raise EdfError("%s: %d group(s) covering %d record(s), but there "
                           "are %d rows" % (source or "table", len(groups),
                                            sum(groups), len(rows)))
        if any(n < 1 for n in groups):
            raise EdfError("%s: an empty group has no row to carry its number "
                           "in the CSV, so it could not be read back"
                           % (source or "table"))
        self.rows = rows
        self.groups = groups
        self.source = source
        self.grammar_source = grammar_source

    @classmethod
    def parse(cls, data, offset, grammar, source, sizes):
        """Read `<u32 group count>` and `sizes` groups of records at `offset`.

        `sizes` comes from the companion file the grammar names -- see
        `companion_sizes`. Returns the table and the offset just past it.
        """
        verify_grammar(grammar, source)
        if offset + COUNT_HEADER_SIZE > len(data):
            raise EdfError("%s: %d byte(s) left, too few for a 4-byte group "
                           "count" % (source, len(data) - offset))
        count = struct.unpack_from(COUNT_HEADER, data, offset)[0]
        pos = offset + COUNT_HEADER_SIZE
        if count != len(sizes):
            raise EdfError(
                "%s: this file states %d group(s) and %s describes %d -- the "
                "two do not line up, and nothing else says where a group ends"
                % (source, count, grammar.groups.file, len(sizes)))
        rows = []
        for i, size in enumerate(sizes):
            for j in range(size):
                row = {}
                for name, ftype in grammar.fields:
                    row[name], pos = read_field(
                        data, pos, ftype,
                        "%s group %d record %d field %s" % (source, i, j, name))
                rows.append(row)
        return cls(grammar, rows, list(sizes), source=source,
                   grammar_source="hand-derived (EDF_TABLE_GRAMMARS)"), pos

    def to_bytes(self):
        where = self.source or "table"
        out = bytearray(struct.pack(COUNT_HEADER, len(self.groups)))
        for i, row in enumerate(self.rows):
            for name, ftype in self.grammar.fields:
                try:
                    out += write_field(row[name], ftype)
                except ValueError as exc:
                    raise EdfError("%s record %d field %s: %s"
                                   % (where, i, name, exc))
        return bytes(out)

    @classmethod
    def from_csv(cls, csv_path, grammar):
        t = cls(grammar, [], [], source=os.path.basename(csv_path),
                grammar_source=os.path.basename(csv_path))
        t.import_csv(csv_path)
        return t

    def export_csv(self, path):
        names = [n for n, _ in self.grammar.fields]
        blocks = [i for i, n in enumerate(self.groups) for _ in range(n)]
        _write_csv(path, [BLOCK_COLUMN] + names,
                   ([str(b)] + [escape_text(str(row[n])) for n in names]
                    for b, row in zip(blocks, self.rows)))

    def import_csv(self, path):
        leads, rows = _read_csv(path, self.grammar.fields, lead=BLOCK_COLUMN)
        where = os.path.basename(path)
        groups = []
        for i, block in enumerate(leads):
            if groups and block == len(groups) - 1:
                groups[-1] += 1
            elif block == len(groups):
                groups.append(1)
            else:
                raise ValueError(
                    "%s line %d: group %d after group %d -- the groups are "
                    "numbered from 0 upwards with no gaps, and their rows are "
                    "written back in the order they appear, so they must stay "
                    "grouped and in group order"
                    % (where, i + 2, block, len(groups) - 1))
        self.rows = rows
        self.groups = groups
        return rows


def companion_sizes(spec, tables, source):
    """The group lengths `spec` names, read out of a parsed companion file."""
    if not 0 <= spec.table < len(tables):
        raise EdfError("%s: %s has %d table(s), so there is no table %d to "
                       "take group lengths from"
                       % (source, spec.file, len(tables), spec.table))
    table = tables[spec.table]
    if not isinstance(table, NestTable):
        raise EdfError("%s: %s table %d has no nested runs, so it cannot say "
                       "how long a group is" % (source, spec.file, spec.table))
    names = [run.name for run in table.grammar.runs]
    picked = []
    for name in spec.runs:
        if name not in names:
            raise EdfError("%s: %s table %d has no run called %r -- it has %s"
                           % (source, spec.file, spec.table, name,
                              ", ".join(names)))
        picked.append(table.runs[names.index(name)])
    sizes = [spec.plus + sum(len(run[i]) for run in picked)
             for i in range(len(table.rows))]
    for i, n in enumerate(sizes):
        if n < 1:
            raise EdfError(
                "%s: %s block %d measures an empty group, which would have no "
                "row to carry its number in the CSV and could not be read "
                "back" % (source, spec.file, i))
    return sizes


def companion_reader(path):
    """Parse the companion files of the `.edf` at `path`, on demand and once.

    A localized table sits one directory below the table it names --
    `DataTable/en-ph/NDMap.edf` beside `DataTable/Map.edf` -- so a companion
    is looked for next to the file first and in its parent directory second.
    It is parsed with no companion of its own, which is all any of them needs
    and is also what stops a cycle from recursing.
    """
    here = os.path.dirname(os.path.abspath(path))
    cache = {}

    def read(name):
        key = name.lower()
        if key not in cache:
            for folder in (here, os.path.dirname(here)):
                candidate = os.path.join(folder, name)
                if os.path.isfile(candidate):
                    break
            else:
                raise EdfError(
                    "%s says how long %s's groups are, and is neither next to "
                    "it nor one directory up"
                    % (name, os.path.basename(path)))
            grammar = grammar_for(name)
            if grammar is None:
                raise EdfError("%s has no grammar of its own, so it cannot "
                               "say how long another file's groups are" % name)
            payload, _key = decrypt_file(candidate)
            cache[key] = parse_var_tables(payload, grammar, name)
        return cache[key]

    return read


def parse_var_tables(payload, grammars, source="EDF payload",
                     companion=None):
    """Parse a count-only payload into `VarTable`s, consuming every byte.

    The closure test is the chain's: the walk has to land exactly on the last
    byte. A grammar that stops early has read a count or a length at the wrong
    offset, and everything after it is wrong too.

    `companion` resolves a file name to that file's parsed tables, for the one
    grammar kind whose lengths are not in its own payload -- pass
    `companion_reader(path)`. Only reading needs it; `build_var_tables` never
    does.
    """
    tables = []
    offset = 0
    for i, grammar in enumerate(grammars):
        if grammar is INFERRED_CHAIN:
            table, offset = _parse_inferred_chain(
                payload, offset, "%s#%d" % (source, i))
            tables.append(table)
            continue
        if isinstance(grammar, GroupGrammar):
            where = "%s#%d" % (source, i)
            if companion is None:
                raise EdfError(
                    "%s: this table's group lengths are in %s, and no way to "
                    "read it was given -- parse with "
                    "companion=companion_reader(path)"
                    % (where, grammar.groups.file))
            table, offset = GroupTable.parse(
                payload, offset, grammar, where,
                companion_sizes(grammar.groups, companion(grammar.groups.file),
                                where))
            tables.append(table)
            continue
        if isinstance(grammar, PoolGrammar):
            reader = PoolTable
        elif isinstance(grammar, NestGrammar):
            reader = NestTable
        elif isinstance(grammar, BlockGrammar):
            reader = BlockTable
        elif isinstance(grammar, ChainGrammar):
            reader = ChainTable
        else:
            reader = VarTable
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
    """Rebuild a count-only payload from `VarTable`s.

    An `rf_dat.Table` among them is an INFERRED_CHAIN one, and is written back
    with the 8-byte chain header `build_table_chain` writes: its own
    `to_bytes` writes the server's 12-byte header, whose middle `field_count`
    a chain table does not carry.
    """
    out = bytearray()
    for table in tables:
        if isinstance(table, Table):
            out += struct.pack(CHAIN_HEADER, len(table.rows), table.rec_size)
            out += table.to_bytes()[HEADER_SIZE:]
        else:
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
    if isinstance(grammar, ChainGrammar):
        doc["kind"] = "chain"
        doc["record_bytes"] = chain_record_size(grammar)
        doc.update(_layout_doc(grammar.fields))
    elif isinstance(grammar, PoolGrammar):
        doc["kind"] = "pool"
        doc["slot_type"] = grammar.slot_type
        doc["slots"] = grammar.slots
        doc["string_count_type"] = grammar.count
        doc["item"] = grammar.item
        doc["record_bytes"] = pool_record_size(grammar)
        doc.update(_layout_doc(grammar.lead))
    elif isinstance(grammar, GroupGrammar):
        doc["kind"] = "group"
        doc["companion"] = {"file": grammar.groups.file,
                            "table": grammar.groups.table,
                            "runs": list(grammar.groups.runs),
                            "plus": grammar.groups.plus}
        doc.update(_layout_doc(grammar.fields))
    elif isinstance(grammar, NestGrammar):
        doc["kind"] = "nest"
        doc.update(_layout_doc(grammar.head))
        doc.update(_layout_doc(grammar.tail, "tail_"))
        doc["runs"] = [
            dict({"name": run.name, "count_type": run.count},
                 **_layout_doc(run.fields)) for run in grammar.runs]
    elif isinstance(grammar, BlockGrammar):
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


def _read_layout(doc, where, prefix="", may_be_empty=False):
    fields = [(fld["name"], fld["type"]) for fld in doc[prefix + "fields"]]
    if fields or not may_be_empty:
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
    if doc.get("kind") == "chain":
        grammar = ChainGrammar(_read_layout(doc, where))
        verify_grammar(grammar, where)
        if chain_record_size(grammar) != doc["record_bytes"]:
            raise EdfError("%s is inconsistent: the grammar describes a "
                           "%d-byte record, the header says %d"
                           % (where, chain_record_size(grammar),
                              doc["record_bytes"]))
        return grammar, doc
    if doc.get("kind") == "pool":
        grammar = PoolGrammar(_read_layout(doc, where), doc["slot_type"],
                              doc["slots"], doc["string_count_type"],
                              doc["item"])
        verify_grammar(grammar, where)
        if pool_record_size(grammar) != doc["record_bytes"]:
            raise EdfError("%s is inconsistent: the grammar describes a "
                           "%d-byte record, the header says %d"
                           % (where, pool_record_size(grammar),
                              doc["record_bytes"]))
        return grammar, doc
    if doc.get("kind") == "group":
        companion = doc["companion"]
        grammar = GroupGrammar(
            CompanionRuns(companion["file"], companion["table"],
                          tuple(companion["runs"]), companion["plus"]),
            _read_layout(doc, where))
    elif doc.get("kind") == "nest":
        grammar = NestGrammar(
            _read_layout(doc, where),
            [NestRun(run["name"], run["count_type"],
                     _read_layout(run, "%s run %s" % (where, run["name"])))
             for run in doc["runs"]],
            _read_layout(doc, where, "tail_", may_be_empty=True))
    elif doc.get("kind") == "block":
        grammar = BlockGrammar(_read_layout(doc, where),
                               doc["item_count_type"],
                               _read_layout(doc, where, "item_"))
    else:
        grammar = _read_layout(doc, where)
    verify_grammar(grammar, where)
    return grammar, doc

def write_stamp_json(table, path, table_name="", source=""):
    """Freeze a stamped block's schema plus the two facts its body cannot state.

    The schema half is `rf_dat.write_schema_json` verbatim -- a stamped body is
    an ordinary chain table and deserves the ordinary schema doc, redundant
    totals and all. The stamp's index byte and whether the body is headed are
    then added to that same doc rather than to `rf_dat`'s writer, which knows
    nothing about this container and should keep knowing nothing.
    """
    write_schema_json(table.schema, path, dat_name=table_name, source=source,
                      header_field_count=table.table.field_count)
    with open(path, "r", encoding="ascii") as f:
        doc = json.load(f)
    doc["stamp_index"] = table.index
    doc["stamp_headed"] = table.headed
    with open(path, "w", encoding="ascii", newline="\n") as f:
        json.dump(doc, f, indent=1)
        f.write("\n")


def read_stamp_json(path):
    """`(schema, doc)` for a stamped block, refusing a doc missing its stamp."""
    schema, doc = read_schema_json(path)
    for key in ("stamp_index", "stamp_headed"):
        if key not in doc:
            raise EdfError("%s: no %s -- this is a schema for a plain table, "
                           "not for a stamped block" % (path, key))
    return schema, doc


# --------------------------------------------------------------------------
# the repo-facing layer: a file's tables as a directory of CSVs
# --------------------------------------------------------------------------
#
# BACKLOG #100 wires this into rf_repo.py's client root, so what
# `--check-tables` proves in a temp directory is exactly what rf-data keeps on
# disk: one directory per `.edf`, `00.csv` .. `NN.csv` inside it, and each
# table's frozen layout beside it as `NN.json`. The reading and the builder
# are paired here rather than sniffed at the call site -- a chain table and a
# .dat table are both `rf_dat.Table` and differ only in the header they are
# written back with, so which reading was used has to be recorded, not guessed
# a second time.

PAYLOAD_BUILDERS = {
    "chain": build_table_chain,
    "grammar": build_var_tables,
    "dat": build_dat_tables,
    "stamped": build_stamped_tables,
}

# Which table class a frozen grammar's `kind` belongs to. read_grammar_json
# rebuilds the grammar itself; this says who reads a CSV with it.
GRAMMAR_TABLES = {
    "flat": VarTable,
    "block": BlockTable,
    "pool": PoolTable,
    "chain": ChainTable,
    "nest": NestTable,
    "group": GroupTable,
}
GRAMMAR_TABLE_CLASSES = (VarTable, BlockTable, PoolTable, ChainTable,
                         NestTable, GroupTable)

_LAYOUT_NAME = re.compile(r"^(\d+)\.json$")


class EdfUnhandled(EdfError):
    """The container opens, but its payload matches none of the four readings.

    Distinct from an ordinary EdfError on purpose: a file nobody has read yet
    is not a broken file. `--check-tables` reports it as unhandled, and
    rf_repo.py leaves it in files/ as a verbatim blob rather than refusing to
    import the whole install over it.
    """


def classify_tables(payload, source="EDF payload", companion=None):
    """`(kind, tables)` for a decoded payload -- the four readings, in order.

    A registered grammar is tried alone and its failure is fatal: something is
    wrong with the grammar or with the file, and either way a file whose
    layout we claim to know must not fall through to a guess. Without one the
    chain walk goes first, then the server's plain .dat container, then the
    stamped directory. A payload that *is* stamped but whose two halves
    contradict each other raises StampedDirectoryError rather than being
    reported as unread.

    `companion` is `companion_reader(path)` -- only a group grammar needs it,
    and only for reading; no builder ever does.
    """
    name = os.path.basename(source)
    grammar = grammar_for(name)
    if grammar is not None:
        try:
            return "grammar", parse_var_tables(payload, grammar, name,
                                               companion=companion)
        except SchemaError as exc:
            raise EdfError("its grammar does not fit: %s"
                           % str(exc).split(": ", 1)[-1])
    try:
        return "chain", parse_table_chain(payload, name)
    except SchemaError as exc:
        chain_why = str(exc).split(": ", 1)[-1]
    try:
        return "dat", parse_dat_tables(payload, name)
    except SchemaError:
        pass
    try:
        return "stamped", parse_stamped_tables(payload, name)
    except StampedDirectoryError:
        raise
    except (SchemaError, EdfError):
        # Reported against the chain reading: it is the one that gets furthest
        # into these payloads, so its message says the most about where the
        # walk broke.
        raise EdfUnhandled("not a table chain: %s" % chain_why)


def read_tables(path, companion=True):
    """`(payload, key, kind, tables)` for the `.edf` file at `path`.

    The key comes back decoded, ready to hand to `encrypt`. It is per file and
    travels inside it, so a repo that wants to rebuild the file byte for byte
    later -- with the install no longer there to read it back off -- has to
    keep its own copy.
    """
    payload, key = decrypt_file(path)
    kind, tables = classify_tables(
        payload, path, companion=companion_reader(path) if companion else None)
    return payload, key, kind, tables


def build_payload(kind, tables):
    """Rebuild a payload from tables that were read as `kind`."""
    if kind not in PAYLOAD_BUILDERS:
        raise EdfError("%r is not a payload reading -- it is one of %s"
                       % (kind, ", ".join(sorted(PAYLOAD_BUILDERS))))
    return PAYLOAD_BUILDERS[kind](tables)


def export_tables(tables, csv_dir, schema_dir, name=""):
    """Write each table as `NN.csv`, with its frozen layout as `NN.json`.

    A block, pool or nested table writes its second region as a further CSV
    beside its own -- `00.items.csv`, `00.<run>.csv` -- named by the table
    class, not here. The layout JSON is what `import_tables` reads the class
    back off: a stamp doc carries `stamp_index`, a grammar doc `kind`, and a
    plain schema doc neither.
    """
    os.makedirs(csv_dir, exist_ok=True)
    os.makedirs(schema_dir, exist_ok=True)
    for i, table in enumerate(tables):
        csv_path = os.path.join(csv_dir, "%02d.csv" % i)
        layout_path = os.path.join(schema_dir, "%02d.json" % i)
        table.export_csv(csv_path)
        where = "%s#%d" % (name, i)
        if isinstance(table, StampTable):
            write_stamp_json(table, layout_path, table_name=where,
                             source=table.schema_source)
        elif isinstance(table, GRAMMAR_TABLE_CLASSES):
            write_grammar_json(table.grammar, layout_path, table_name=where,
                               source=table.grammar_source)
        else:
            write_schema_json(table.schema, layout_path, dat_name=where,
                              source=table.schema_source,
                              header_field_count=table.field_count)


def table_indices(schema_dir):
    """`[0, 1, ... n-1]` from a schema directory's `NN.json` layouts.

    A gap means a layout was deleted or renamed, and every table after it
    would silently move: a payload is its tables laid end to end, so table 3
    becoming table 2 rewrites the file from there on. Refuse instead.
    """
    try:
        names = os.listdir(schema_dir)
    except OSError:
        raise EdfError("%s: no frozen layouts here -- nothing to rebuild from"
                       % schema_dir)
    idx = sorted(int(m.group(1))
                 for m in (_LAYOUT_NAME.match(n) for n in names) if m)
    if not idx:
        raise EdfError("%s: no NN.json layout here -- nothing to rebuild from"
                       % schema_dir)
    if idx != list(range(len(idx))):
        raise EdfError(
            "%s: the layouts are numbered %s -- they must run from 00 upwards "
            "with no gaps, because a payload is its tables laid end to end and "
            "dropping one moves every table after it"
            % (schema_dir, ", ".join("%02d" % i for i in idx)))
    return idx


def import_tables(csv_dir, schema_dir):
    """Read a pair of directories written by `export_tables` back into tables."""
    out = []
    for i in table_indices(schema_dir):
        layout_path = os.path.join(schema_dir, "%02d.json" % i)
        csv_path = os.path.join(csv_dir, "%02d.csv" % i)
        with open(layout_path, "r", encoding="ascii") as f:
            doc = json.load(f)
        if "stamp_index" in doc:
            schema, doc = read_stamp_json(layout_path)
            out.append(StampTable.from_csv(
                csv_path, schema, doc["stamp_index"], doc["stamp_headed"],
                field_count=doc.get("header_field_count")))
        elif "kind" in doc:
            grammar, doc = read_grammar_json(layout_path)
            if doc["kind"] not in GRAMMAR_TABLES:
                raise EdfError("%s: %r is not a grammar kind -- it is one of %s"
                               % (layout_path, doc["kind"],
                                  ", ".join(sorted(GRAMMAR_TABLES))))
            out.append(GRAMMAR_TABLES[doc["kind"]].from_csv(csv_path, grammar))
        else:
            schema, doc = read_schema_json(layout_path)
            out.append(Table.from_csv(
                csv_path, schema, field_count=doc.get("header_field_count")))
    return out


def _csv_round_trip(tables, name, tmp, build):
    """Write every table out as CSV + frozen layout, read it back, rebuild.

    All four payload models come through here, and each one freezes the layout
    its own reader needs -- a schema for a chain or .dat table, a grammar for a
    variable-record one. `build` is the matching payload builder, passed in
    rather than sniffed: a chain table and a .dat table are both
    `rf_dat.Table` and differ only in the header they are written back with,
    so the caller has to say which one it read.
    """
    export_tables(tables, tmp, tmp, name)
    return build(import_tables(tmp, tmp))


def _check_tables(paths):
    """payload -> tables -> CSV+layout -> tables -> payload, diffed byte for byte.

    The CSV hop is the point. Parsing a payload proves only that the bytes
    fit; writing the rows out as text, reading them back through the frozen
    layout, and reproducing the payload to the byte is what makes a file safe
    to *edit*. A file matching none of the four readings is reported as
    unhandled, never silently accepted.
    """
    counts = {"chain": 0, "grammar": 0, "dat": 0, "stamped": 0}
    failed = skipped = 0
    for path in paths:
        name = os.path.basename(path)
        try:
            payload, _key = decrypt_file(path)
        except EdfError as exc:
            print("ERROR  %-28s %s" % (name, exc))
            failed += 1
            continue
        try:
            kind, tables = classify_tables(payload, path,
                                           companion=companion_reader(path))
        except EdfUnhandled as exc:
            print("SKIP   %-28s %s" % (name, exc))
            skipped += 1
            continue
        except SchemaError as exc:
            print("FAIL   %-28s %s" % (name, str(exc).split(": ", 1)[-1]))
            failed += 1
            continue
        try:
            with tempfile.TemporaryDirectory() as tmp:
                blob = _csv_round_trip(tables, name, tmp,
                                       PAYLOAD_BUILDERS[kind])
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
          "%d grammar, %d dat, %d stamped), %d failed, %d unhandled"
          % (sum(counts.values()), counts["chain"], counts["grammar"],
             counts["dat"], counts["stamped"], failed, skipped))
    return 1 if failed else 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("file", nargs="+",
                        help="the .edf file(s) to read, or the payload to --encode")
    parser.add_argument("--check", action="store_true",
                        help="decode then re-encode each file and diff against the original")
    parser.add_argument("--classify", action="store_true",
                        help="report which of the four payload readings each file takes, and why none fits if so")
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
        chains = grammars = dats = stamped = 0
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
                    tables = parse_var_tables(
                        payload, grammar, name,
                        companion=companion_reader(path))
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
                try:
                    blocks = parse_stamped_tables(payload, name)
                except StampedDirectoryError as exc:
                    print("BROKEN %-28s %8d bytes  its directory does not fit: "
                          "%s" % (name, len(payload),
                                  str(exc).split(": ", 1)[-1]))
                    continue
                except (SchemaError, EdfError):
                    print("OTHER  %-28s %8d bytes  %s"
                          % (name, len(payload), why.split(": ", 1)[-1]))
                    continue
                stamped += 1
                print("STAMPD %-28s %8d bytes  %2d block(s)  %s"
                      % (name, len(payload), len(blocks),
                         ", ".join("%dx%d" % (len(b.rows), b.table.rec_size)
                                   for b in blocks[:6])
                         + (", ..." if len(blocks) > 6 else "")))
                continue
            dats += 1
            print("DAT    %-28s %8d bytes  %2d table(s)  %s"
                  % (name, len(payload), len(tables),
                     ", ".join("%dx%d in %d field(s)"
                               % (len(t.rows), t.rec_size, t.field_count)
                               for t in tables[:4])))
        print("\n%d/%d payload(s) are table chains, %d have a hand-derived "
              "grammar, %d are plain .dat containers, %d stamped chain(s)"
              % (chains, len(args.file), grammars, dats, stamped))
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
