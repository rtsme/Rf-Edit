import os
import struct
import tempfile
import unittest

from rf_dat import SchemaError, Table
from rf_edf import (KEY_LENGTH, MAGIC, build_table_chain, decrypt, encrypt,
                    parse_table_chain)


class EdfTests(unittest.TestCase):
    def setUp(self):
        self.key = bytes(range(KEY_LENGTH))

    def test_container_round_trip(self):
        payload = bytes((i * 37 + 11) & 0xff for i in range(4097))
        encoded = encrypt(payload, self.key)
        self.assertEqual(encoded[:len(MAGIC)], MAGIC)
        self.assertEqual(struct.unpack_from("<I", encoded, len(MAGIC))[0],
                         len(payload))
        self.assertEqual(decrypt(encoded), (payload, self.key))
        self.assertEqual(encrypt(*decrypt(encoded)), encoded)

    def test_table_chain_round_trip(self):
        first = Table(
            [("Index", "dword"), ("Code", "string[4]")],
            [{"Index": 7, "Code": "ABCD"},
             {"Index": -1, "Code": "xy"}],
            2, 8, strict_field_count=False)
        second = Table(
            [("Val1", "dword")], [{"Val1": 42}],
            1, 4, strict_field_count=False)
        payload = build_table_chain([first, second])
        parsed = parse_table_chain(payload, "fixture.edf")
        self.assertEqual(len(parsed), 2)
        self.assertEqual(build_table_chain(parsed), payload)
        self.assertEqual(parsed[0].rows[0]["Index"], 7)

    def test_client_inference_supports_codes_and_short_tail(self):
        table = Table(
            [("Index", "dword"), ("Code", "string[4]"),
             ("Val1", "word")],
            [{"Index": 0, "Code": "ABCD", "Val1": 9}],
            3, 10, strict_field_count=False)
        payload = build_table_chain([table])
        parsed = parse_table_chain(payload)
        self.assertEqual(parsed[0].schema,
                         [("Index", "dword"), ("Code", "string[4]"),
                          ("Val1", "word")])
        self.assertEqual(build_table_chain(parsed), payload)

    def test_rejects_wrong_magic_and_length(self):
        encoded = encrypt(b"payload", self.key)
        with self.assertRaises(SchemaError):
            decrypt(b"not an edf")
        with self.assertRaises(SchemaError):
            decrypt(encoded[:-1])

    def test_rejects_truncated_chain(self):
        with self.assertRaises(SchemaError):
            parse_table_chain(struct.pack("<2I", 10, 4) + b"short")

    def test_dat_reader_rejects_short_header_cleanly(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"tiny")
            path = f.name
        try:
            with self.assertRaisesRegex(SchemaError, "too small"):
                Table.open(path)
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
