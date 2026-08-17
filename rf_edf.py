"""Read and write RF Online client-side ``.edf`` containers.

An EDF wraps an encrypted payload like this::

    29-byte magic | uint32 payload size | encrypted payload | 256-byte key

The payload is either an opaque blob or a chain of tables.  Chain tables use
an 8-byte header (record count, record size), followed by fixed-width records.
Unlike server ``.dat`` files they do not store a field count.
"""
import struct

from rf_dat import (SchemaError, Table, decode, field_size, infer_schema,
                    verify_schema)


MAGIC = b"RF Online by OdinTeam s(^O^)z"
KEY_LENGTH = 256
CHAIN_HEADER = "<2I"
CHAIN_HEADER_SIZE = struct.calcsize(CHAIN_HEADER)
_DIGITS = (1, 2, 4, 8, 16, 32, 64, 128)


def _require_key(key):
    key = bytes(key)
    if len(key) != KEY_LENGTH:
        raise SchemaError("EDF key must be exactly %d bytes" % KEY_LENGTH)
    return key


def _decode_key(encoded):
    key = bytearray(_require_key(encoded))
    for i in range(KEY_LENGTH):
        digit = _DIGITS[(i + 1) % len(_DIGITS)]
        key[i] = ((key[i] - digit) if i % 2 == 0
                  else (key[i] + digit)) & 0xff
    key.reverse()
    for i in range(0, KEY_LENGTH, 2):
        key[i], key[i + 1] = key[i + 1], key[i]
    return bytes(key)


def _encode_key(decoded):
    key = bytearray(_require_key(decoded))
    for i in range(0, KEY_LENGTH, 2):
        key[i], key[i + 1] = key[i + 1], key[i]
    key.reverse()
    for i in range(KEY_LENGTH):
        digit = _DIGITS[(i + 1) % len(_DIGITS)]
        key[i] = ((key[i] + digit) if i % 2 == 0
                  else (key[i] - digit)) & 0xff
    return bytes(key)


def decrypt(blob):
    """Return ``(plaintext_payload, decoded_key)`` for an EDF byte string."""
    minimum = len(MAGIC) + 4 + KEY_LENGTH
    if len(blob) < minimum:
        raise SchemaError("EDF is too small to hold its header and key")
    if blob[:len(MAGIC)] != MAGIC:
        raise SchemaError("not an OdinTeam RF Online EDF container")

    payload_size = struct.unpack_from("<I", blob, len(MAGIC))[0]
    expected = len(MAGIC) + 4 + payload_size + KEY_LENGTH
    if len(blob) != expected:
        raise SchemaError(
            "EDF header implies %d bytes but the file is %d bytes"
            % (expected, len(blob)))

    body_start = len(MAGIC) + 4
    body = bytearray(blob[body_start:body_start + payload_size])
    key = _decode_key(blob[-KEY_LENGTH:])
    for i in range(len(body)):
        k = key[(i + 1) % KEY_LENGTH]
        body[i] = ((body[i] - k) if i % 2 == 0
                   else (body[i] + k)) & 0xff
    return bytes(body), key


def encrypt(payload, key):
    """Build a deterministic EDF using a decoded 256-byte key."""
    key = _require_key(key)
    if len(payload) > 0xffffffff:
        raise SchemaError("EDF payload is too large for its 32-bit header")
    body = bytearray(payload)
    for i in range(len(body)):
        k = key[(i + 1) % KEY_LENGTH]
        body[i] = ((body[i] + k) if i % 2 == 0
                   else (body[i] - k)) & 0xff
    return (MAGIC + struct.pack("<I", len(payload)) + bytes(body)
            + _encode_key(key))


def decrypt_file(path):
    with open(path, "rb") as f:
        return decrypt(f.read())


def _table_from_records(data, count, rec_size, source):
    if rec_size == 0:
        raise SchemaError("%s has a zero-byte record" % source)
    if count == 0:
        if rec_size % 4:
            raise SchemaError(
                "%s is empty and its %d-byte record cannot be represented "
                "safely" % (source, rec_size))
        schema = [("Val%d" % (i + 1), "dword")
                  for i in range(rec_size // 4)]
        schema_source = "placeholder (empty EDF table)"
    else:
        # Client tables use many 4-byte item/quest codes. Inspect every row
        # before calling a slot text: a numeric field can look printable in
        # the first few hundred records and contain control bytes later.
        records = [data[i * rec_size:(i + 1) * rec_size]
                   for i in range(count)]
        schema = infer_schema(records, rec_size, string_widths=(4, 64),
                              allow_short_numbers=True)
        schema_source = "inferred from records"
    verify_schema(schema, len(schema), rec_size)

    rows = []
    for row_index in range(count):
        row, pos = {}, row_index * rec_size
        for name, ftype in schema:
            width = field_size(ftype)
            row[name] = decode(data[pos:pos + width], ftype)
            pos += width
        rows.append(row)
    return Table(schema, rows, len(schema), rec_size, source=source,
                 schema_source=schema_source, strict_field_count=False)


def parse_table_chain(payload, source="EDF payload"):
    """Parse an EDF table-chain payload, consuming every byte.

    Raises ``SchemaError`` when the payload is not a clean table chain.  That
    lets callers preserve unsupported payloads as opaque blobs instead of
    guessing at a structure and risking corruption.
    """
    tables = []
    offset = 0
    while offset < len(payload):
        remaining = len(payload) - offset
        if remaining < CHAIN_HEADER_SIZE:
            raise SchemaError(
                "%s has %d trailing byte(s), not another table header"
                % (source, remaining))
        count, rec_size = struct.unpack_from(CHAIN_HEADER, payload, offset)
        body_size = count * rec_size
        body_start = offset + CHAIN_HEADER_SIZE
        body_end = body_start + body_size
        if body_end > len(payload):
            raise SchemaError(
                "%s table %d claims %d records x %d bytes beyond EOF"
                % (source, len(tables), count, rec_size))
        label = "%s#%d" % (source, len(tables))
        tables.append(_table_from_records(
            payload[body_start:body_end], count, rec_size, label))
        offset = body_end
    if not tables:
        raise SchemaError("%s contains no tables" % source)
    return tables


def build_table_chain(tables):
    """Build an EDF table-chain payload from ``rf_dat.Table`` objects."""
    out = bytearray()
    for table in tables:
        verify_schema(table.schema, table.field_count, table.rec_size,
                      check_field_count=table.strict_field_count)
        out += struct.pack(CHAIN_HEADER, len(table.rows), table.rec_size)
        standard = table.to_bytes()
        out += standard[12:]
    return bytes(out)
