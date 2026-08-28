"""Unit tests for the `.edf` container codec and its table-chain payload.

These are the checks that do not need a client install: synthetic containers
and chains, plus the refusals that keep a payload from being mis-parsed. The
check that matters most needs real files and lives in the CLI:

    python rf_edf.py <DataTable>/*.edf <DataTable>/en-ph/*.edf --check-tables

which round-trips every chain payload out to CSV and back and diffs the bytes.

Run:  python -m unittest test_rf_edf -v
"""
import struct
import unittest

from rf_dat import SchemaError, Table, infer_schema
from rf_edf import (CHAIN_HEADER, EDF_MIN_TEXT_SHARE, EDF_STRING_WIDTHS,
                    KEY_LENGTH, MAGIC, EdfError, build_table_chain,
                    chain_layout, classify, decrypt, encrypt,
                    parse_table_chain)


class ContainerTests(unittest.TestCase):
    def setUp(self):
        self.key = bytes(range(KEY_LENGTH))

    def test_round_trip(self):
        payload = bytes((i * 37 + 11) & 0xFF for i in range(4097))
        blob = encrypt(payload, self.key)
        self.assertEqual(blob[:len(MAGIC)], MAGIC)
        self.assertEqual(struct.unpack_from("<I", blob, len(MAGIC))[0],
                         len(payload))
        self.assertEqual(decrypt(blob), (payload, self.key))
        self.assertEqual(encrypt(*decrypt(blob)), blob)

    def test_rejects_wrong_magic_and_truncation(self):
        blob = encrypt(b"payload", self.key)
        with self.assertRaises(EdfError):
            decrypt(b"not an edf, and far too short as well" * 8)
        with self.assertRaises(EdfError):
            decrypt(blob[:-1])

    def test_edf_error_is_a_schema_error(self):
        # One `except SchemaError` has to cover a bad container and a bad
        # table alike, or every caller needs two handlers.
        self.assertTrue(issubclass(EdfError, SchemaError))


def _table(schema, rows, rec_size):
    return Table(schema, rows, len(schema), rec_size, strict_field_count=False)


class ChainTests(unittest.TestCase):
    def test_chain_round_trip(self):
        first = _table([("Index", "dword"), ("Code", "string[4]")],
                       [{"Index": 7, "Code": "ABCD"},
                        {"Index": -1, "Code": "xy"}], 8)
        second = _table([("Val1", "dword")], [{"Val1": 42}], 4)
        payload = build_table_chain([first, second])
        self.assertEqual(chain_layout(payload), [(2, 8), (1, 4)])
        parsed = parse_table_chain(payload, "fixture.edf")
        self.assertEqual(len(parsed), 2)
        self.assertEqual(parsed[0].rows[0]["Index"], 7)
        self.assertEqual(build_table_chain(parsed), payload)

    def test_short_trailing_field_survives(self):
        # Character.edf's fifth table is 46 bytes per record: without 2-byte
        # numbers it cannot be laid out at all.
        table = _table([("Index", "dword"), ("Code", "string[4]"),
                        ("Val1", "word")],
                       [{"Index": 0, "Code": "ABCD", "Val1": 9}], 10)
        payload = build_table_chain([table])
        parsed = parse_table_chain(payload)
        self.assertEqual(parsed[0].schema,
                         [("Index", "dword"), ("Code", "string[4]"),
                          ("Val1", "word")])
        self.assertEqual(build_table_chain(parsed), payload)

    def test_empty_table_is_numbers_not_text(self):
        payload = struct.pack(CHAIN_HEADER, 0, 8)
        parsed = parse_table_chain(payload)
        self.assertEqual(parsed[0].schema,
                         [("Val1", "dword"), ("Val2", "dword")])
        self.assertEqual(build_table_chain(parsed), payload)

    def test_refuses_a_chain_that_does_not_close(self):
        with self.assertRaises(EdfError):
            chain_layout(struct.pack(CHAIN_HEADER, 10, 4) + b"short")
        with self.assertRaises(EdfError):
            chain_layout(struct.pack(CHAIN_HEADER, 1, 4) + b"body" + b"\x00\x00")
        with self.assertRaises(EdfError):
            chain_layout(struct.pack(CHAIN_HEADER, 37, 0))

    def test_classify_reports_rather_than_raises(self):
        layout, why = classify(struct.pack(CHAIN_HEADER, 1, 4) + b"body")
        self.assertEqual(layout, [(1, 4)])
        self.assertEqual(why, "")
        layout, why = classify(struct.pack(CHAIN_HEADER, 6360, 0), "NDLanguage")
        self.assertIsNone(layout)
        self.assertIn("NDLanguage", why)


class NarrowStringTests(unittest.TestCase):
    """A 4-byte slot is nearly no evidence, so it is held to plain ASCII."""

    def _schema(self, records, rec_size):
        return infer_schema(records, rec_size,
                            string_widths=EDF_STRING_WIDTHS,
                            allow_short_numbers=True,
                            min_text_share=EDF_MIN_TEXT_SHARE)

    def test_ascii_code_is_a_string(self):
        records = [b"\x00\x00\x00\x00BWB0", b"\x01\x00\x00\x00BWF1"]
        self.assertEqual(self._schema(records, 8),
                         [("Index", "dword"), ("Code", "string[4]")])

    def test_minus_one_sentinel_is_not_a_string(self):
        records = [b"\x00\x00\x00\x00\xff\xff\xff\xff",
                   b"\x01\x00\x00\x00\xff\xff\xff\xff"]
        self.assertEqual(self._schema(records, 8),
                         [("Index", "dword"), ("Val1", "dword")])

    def test_wide_slot_wins_over_narrow(self):
        # "WARRIOR" in a 64-byte slot must not be chopped into "WARR" by its
        # own first four characters.
        records = [b"\x00\x00\x00\x00" + b"WARRIOR".ljust(64, b"\x00"),
                   b"\x01\x00\x00\x00" + b"COMMANDO".ljust(64, b"\x00")]
        self.assertEqual(self._schema(records, 68),
                         [("Index", "dword"), ("Code", "string[64]")])

    def test_server_inference_is_unchanged(self):
        # No string_widths, no allow_short_numbers: the historical behaviour,
        # high bytes and all. Varying high bytes stand in for legacy Korean
        # text -- a *uniform* run of one high byte is BACKLOG #47's fill-run
        # sentinel, not text, and is covered separately below.
        records = [b"\x00\x00\x00\x00" + bytes([0xB0, 0xB1, 0xB2, 0xB3,
                                                  0xB4, 0xB5, 0xB6, 0xB7]),
                   b"\x01\x00\x00\x00" + bytes([0xB1, 0xB2, 0xB3, 0xB4,
                                                 0xB5, 0xB6, 0xB7, 0xB8])]
        self.assertEqual(infer_schema(records, 12, width=8),
                         [("Index", "dword"), ("Code", "string[8]")])

    def test_fill_run_is_not_a_string(self):
        # A slot that is one repeated high byte in every record -- the
        # client's empty-slot fill (e.g. 64 x 0xFF) -- is not text, at any
        # width, not just the narrow (<8-byte) slots ascii_only covers.
        records = [b"\x00\x00\x00\x00" + bytes([0xFF] * 8),
                   b"\x01\x00\x00\x00" + bytes([0xFF] * 8)]
        self.assertEqual(infer_schema(records, 12, width=8),
                         [("Index", "dword"), ("Val1", "dword"),
                          ("Val2", "dword")])

    def test_fill_run_does_not_block_real_text_elsewhere_in_the_slot(self):
        # A slot that is fill in most records but real text in at least one
        # still reads as a string -- the fill records just don't count as
        # evidence on their own.
        records = [b"\x00\x00\x00\x00" + bytes([0xFF] * 8),
                   b"\x01\x00\x00\x00" + b"ITEM0001"]
        self.assertEqual(infer_schema(records, 12, width=8),
                         [("Index", "dword"), ("Code", "string[8]")])

    def test_mostly_fill_wide_slot_is_rejected_below_the_share(self):
        # BACKLOG #50: "at least one text record" (min_text_share=0.0, the
        # default) is enough for a 32-byte name slot to read as a string even
        # when almost every record in it is the empty-slot fill run -- most
        # of its *values* are then junk. Below EDF_STRING_WIDTHS's threshold
        # the slot should fall back to numbers instead.
        fill = bytes([0xFF] * 32)
        records = ([b"\x00\x00\x00\x00" + b"WARRIOR".ljust(32, b"\x00")] +
                   [struct.pack("<I", i) + fill for i in range(1, 9)])
        schema = infer_schema(records, 36, string_widths=(32,),
                              min_text_share=EDF_MIN_TEXT_SHARE)
        self.assertNotIn("Code", [name for name, _ in schema])
        self.assertEqual([ftype for _, ftype in schema],
                         ["dword"] * 9)

    def test_wide_name_slot_is_kept_above_the_share(self):
        # The same shape, but with enough real names that the share clears
        # the threshold -- this is Character.edf's WARRIOR/COMMANDO column.
        fill = bytes([0xFF] * 32)
        names = [b"WARRIOR", b"COMMANDO", b"RANGER", b"SPIRITUALIST"]
        records = [struct.pack("<I", i) + n.ljust(32, b"\x00")
                   for i, n in enumerate(names)]
        records += [struct.pack("<I", i) + fill for i in range(4, 9)]
        schema = infer_schema(records, 36, string_widths=(32,),
                              min_text_share=EDF_MIN_TEXT_SHARE)
        self.assertEqual(schema, [("Index", "dword"), ("Code", "string[32]")])


if __name__ == "__main__":
    unittest.main()
