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
mix in length-prefixed strings. `classify()` says which file is which and why,
and `parse_table_chain` refuses rather than guessing -- a payload that is not
a chain must stay an opaque blob until someone reads the client's reader for
it, because a plausible-looking mis-parse would corrupt the file on write. See
`docs/knowledge/edf-payload-tables.md` for the per-file evidence.

Usage:
    python rf_edf.py <file.edf> ... --check          # decode+re-encode, diff vs original
    python rf_edf.py <file.edf> ... --classify       # chain or not, and why
    python rf_edf.py <file.edf> ... --check-tables   # payload -> CSV -> payload, byte-exact
    python rf_edf.py <file.edf> --out payload.bin --key-out key.bin
    python rf_edf.py payload.bin --encode --key key.bin --out file.edf

    from rf_edf import decrypt, encrypt
        payload, key = decrypt(open("Item.edf", "rb").read())
        assert encrypt(payload, key) == open("Item.edf", "rb").read()

    from rf_edf import parse_table_chain, build_table_chain
        tables = parse_table_chain(payload, "Store.edf")
        assert build_table_chain(tables) == payload
"""
import argparse
import os
import struct
import sys
import tempfile

from rf_dat import (HEADER_SIZE, SchemaError, Table, decode, field_size,
                    infer_schema, read_schema_json, verify_schema,
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


def _check_tables(paths):
    """payload -> tables -> CSV+schema -> tables -> payload, diffed byte for byte.

    The CSV hop is the point. Parsing a payload proves only that the numbers
    fit; writing the rows out as text, reading them back through the frozen
    schema, and reproducing the payload to the byte is what makes a chain file
    safe to *edit*. Files that are not chains are reported as unhandled, never
    silently accepted.
    """
    checked = failed = skipped = 0
    for path in paths:
        name = os.path.basename(path)
        try:
            payload, _key = decrypt_file(path)
        except EdfError as exc:
            print("ERROR  %-28s %s" % (name, exc))
            failed += 1
            continue
        try:
            tables = parse_table_chain(payload, name)
        except SchemaError as exc:
            print("SKIP   %-28s not a table chain: %s"
                  % (name, str(exc).split(": ", 1)[-1]))
            skipped += 1
            continue
        try:
            with tempfile.TemporaryDirectory() as tmp:
                rebuilt = []
                for i, table in enumerate(tables):
                    csv_path = os.path.join(tmp, "%02d.csv" % i)
                    schema_path = os.path.join(tmp, "%02d.json" % i)
                    table.export_csv(csv_path)
                    write_schema_json(table.schema, schema_path,
                                      dat_name="%s#%d" % (name, i),
                                      source=table.schema_source,
                                      header_field_count=table.field_count)
                    schema, doc = read_schema_json(schema_path)
                    rebuilt.append(Table.from_csv(
                        csv_path, schema,
                        field_count=doc.get("header_field_count")))
                blob = build_table_chain(rebuilt)
        except (SchemaError, ValueError, OSError) as exc:
            print("FAIL   %-28s %s" % (name, exc))
            failed += 1
            continue
        if blob == payload:
            print("OK     %-28s %8d bytes  %2d table(s), %d row(s)"
                  % (name, len(payload), len(tables),
                     sum(len(t.rows) for t in tables)))
            checked += 1
        else:
            where = next((i for i in range(min(len(blob), len(payload)))
                          if blob[i] != payload[i]), min(len(blob), len(payload)))
            print("FAIL   %-28s rebuilt payload is %d bytes vs %d, first "
                  "difference at offset %d"
                  % (name, len(blob), len(payload), where))
            failed += 1
    print("\n%d chain payload(s) round-trip byte-exact through CSV, "
          "%d failed, %d not a chain" % (checked, failed, skipped))
    return 1 if failed else 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("file", nargs="+",
                        help="the .edf file(s) to read, or the payload to --encode")
    parser.add_argument("--check", action="store_true",
                        help="decode then re-encode each file and diff against the original")
    parser.add_argument("--classify", action="store_true",
                        help="report whether each payload is a table chain, and why not if it isn't")
    parser.add_argument("--check-tables", action="store_true",
                        help="round-trip each chain payload through CSV and diff the bytes")
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
        chains = 0
        for path in args.file:
            try:
                payload, _key = decrypt_file(path)
            except EdfError as exc:
                print("ERROR  %-28s %s" % (os.path.basename(path), exc))
                continue
            layout, why = classify(payload, os.path.basename(path))
            if layout:
                chains += 1
                print("CHAIN  %-28s %8d bytes  %2d table(s)  %s"
                      % (os.path.basename(path), len(payload), len(layout),
                         ", ".join("%dx%d" % (c, r) for c, r in layout[:6])
                         + (", ..." if len(layout) > 6 else "")))
            else:
                print("OTHER  %-28s %8d bytes  %s"
                      % (os.path.basename(path), len(payload),
                         why.split(": ", 1)[-1]))
        print("\n%d/%d payload(s) are table chains"
              % (chains, len(args.file)))
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
