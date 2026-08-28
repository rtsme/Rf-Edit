"""Unit tests for the `.edf` container codec and its table-chain payload.

These are the checks that do not need a client install: synthetic containers
and chains, plus the refusals that keep a payload from being mis-parsed. The
check that matters most needs real files and lives in the CLI:

    python rf_edf.py <DataTable>/*.edf <DataTable>/en-ph/*.edf --check-tables

which round-trips every chain payload out to CSV and back and diffs the bytes.

Run:  python -m unittest test_rf_edf -v
"""
import json
import os
import struct
import tempfile
import unittest

from rf_dat import SchemaError, Table, infer_schema
from rf_edf import (CHAIN_HEADER, CHAIN_HEADER_SIZE, DAT_HEADER, EDF_MIN_TEXT_SHARE,
                    EDF_STRING_WIDTHS, EDF_TABLE_GRAMMARS, KEY_LENGTH, MAGIC,
                    LPSTR, MAX_WPSTR, WPSTR, BlockGrammar, BlockTable,
                    EdfError, PoolGrammar, PoolTable,
                    VarTable, build_dat_tables, build_table_chain,
                    build_var_tables, chain_layout, classify, dat_layout,
                    decrypt, encrypt, grammar_for, parse_dat_tables,
                    parse_table_chain, parse_var_tables, pool_record_size,
                    read_grammar_json, verify_grammar, write_grammar_json)


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


class DatContainerTests(unittest.TestCase):
    """The two files that are the server's own .dat container, unchanged.

    What separates this reading from a guess is the header's `field_count`:
    the schema is inferred from the record bytes alone and then has to agree
    with it. A chain table has no such number, which is why its schema is
    taken on trust and this one is not.
    """

    SCHEMA = [("Index", "dword"), ("Code", "string[16]")]
    REC_SIZE = 20

    def _payload(self, rows, field_count=2):
        body = b""
        for index, code in rows:
            body += struct.pack("<i", index) + code.ljust(16, b"\x00")
        return (struct.pack(DAT_HEADER, len(rows), field_count, self.REC_SIZE)
                + body)

    def test_dat_round_trip(self):
        payload = self._payload([(0, b"ACM"), (1, b"ACF")])
        self.assertEqual(dat_layout(payload), [(2, 2, 20)])
        parsed = parse_dat_tables(payload, "Player.edf")
        self.assertEqual(len(parsed), 1)
        self.assertEqual(parsed[0].schema, self.SCHEMA)
        self.assertEqual(parsed[0].rows[1]["Code"], "ACF")
        self.assertEqual(build_dat_tables(parsed), payload)

    def test_several_tables_end_to_end(self):
        payload = (self._payload([(0, b"ACM"), (1, b"ACF")])
                   + self._payload([(2, b"DEM"), (3, b"DEF")]))
        self.assertEqual(dat_layout(payload), [(2, 2, 20), (2, 2, 20)])
        self.assertEqual(build_dat_tables(parse_dat_tables(payload)), payload)

    def test_refuses_a_walk_that_does_not_close(self):
        payload = self._payload([(0, b"ACM"), (1, b"ACF")])
        with self.assertRaises(EdfError):
            dat_layout(payload + bytes(4))
        with self.assertRaises(EdfError):
            dat_layout(payload[:-1])

    def test_refuses_more_fields_than_bytes(self):
        # This is exactly what a chain header looks like read twelve bytes
        # wide, so it has to be rejected rather than half-read.
        with self.assertRaises(EdfError):
            dat_layout(struct.pack(DAT_HEADER, 1, 99, 4) + b"body")

    def test_refuses_a_field_count_the_records_disagree_with(self):
        # Same bytes, same record size, one wrong number in the header: the
        # walk still closes on the last byte, and the reading is still wrong.
        payload = self._payload([(0, b"ACM"), (1, b"ACF")], field_count=3)
        self.assertEqual(dat_layout(payload), [(2, 3, 20)])
        with self.assertRaises(EdfError) as caught:
            parse_dat_tables(payload, "fixture.edf")
        self.assertIn("declares 3 field(s)", str(caught.exception))

    def test_refuses_an_empty_table(self):
        # Nothing to check the declared field count against, and the field
        # count is the only reason this format is readable at all.
        with self.assertRaises(EdfError):
            parse_dat_tables(struct.pack(DAT_HEADER, 0, 2, 20), "fixture.edf")

    def test_a_chain_payload_is_not_read_as_a_dat(self):
        chain = build_table_chain([_table([("Val1", "dword")],
                                          [{"Val1": 42}], 4)])
        with self.assertRaises(EdfError):
            dat_layout(chain, "fixture.edf")


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

class VariableRecordTests(unittest.TestCase):
    """BACKLOG #46: count-only tables whose records are not all one size.

    The grammar under test is the real `NDStore.edf` one -- a dword, two
    64-byte NUL-padded names and a length-prefixed string -- because it
    exercises every field kind the model has.
    """

    STORE = EDF_TABLE_GRAMMARS["ndstore.edf"]
    LANG = EDF_TABLE_GRAMMARS["ndlanguage.edf"]

    def _payload(self, records):
        """`<u32 count>` then NDStore-shaped records, laid out by hand."""
        out = struct.pack("<I", len(records))
        for i, (name1, name2, text) in enumerate(records):
            out += (struct.pack("<i", i)
                    + name1.ljust(64, b"\x00") + name2.ljust(64, b"\x00")
                    + struct.pack("<I", len(text) + 1) + text + b"\x00")
        return out

    def test_round_trip(self):
        payload = self._payload([(b"WEAPON", b"WEAPON", b"Buy a sword."),
                                 (b"POTION", b"POTION", b"Drink up.")])
        tables = parse_var_tables(payload, self.STORE, "NDStore.edf")
        self.assertEqual(len(tables), 1)
        self.assertEqual([r["Id"] for r in tables[0].rows], [0, 1])
        self.assertEqual(tables[0].rows[0]["Name1"], "WEAPON")
        self.assertEqual(tables[0].rows[0]["Text"], "Buy a sword.")
        self.assertEqual(build_var_tables(tables), payload)

    def test_records_may_be_different_sizes(self):
        # The whole point of the model: one field list, records of unequal
        # length. A fixed-width schema cannot express this at all.
        payload = self._payload([(b"A", b"A", b"x"),
                                 (b"B", b"B", b"a much longer line of text")])
        tables = parse_var_tables(payload, self.STORE, "NDStore.edf")
        self.assertEqual(build_var_tables(tables), payload)

    def test_zstr_keeps_bytes_after_the_terminator(self):
        # NDStore record 18's second name is "COIN EXCHANGE", NULs, and then
        # uninitialised stack the client never reads. rf_dat's string[64]
        # would drop it and the payload would not rebuild; zstr[64] treats
        # only the *trailing* NUL run as padding.
        junk = b"COIN EXCHANGE".ljust(44, b"\x00") + bytes(range(0xC0, 0xD4))
        self.assertEqual(len(junk), 64)
        payload = self._payload([(b"WEAPON", junk, b"Hello.")])
        tables = parse_var_tables(payload, self.STORE, "NDStore.edf")
        self.assertTrue(tables[0].rows[0]["Name2"].startswith("COIN EXCHANGE"))
        self.assertEqual(build_var_tables(tables), payload)

    def test_lpstr_length_is_derived_not_stored(self):
        # Editing the text has to move the length prefix with it, or a CSV
        # edit would need the editor to keep a byte count in step by hand.
        payload = self._payload([(b"WEAPON", b"WEAPON", b"short")])
        tables = parse_var_tables(payload, self.STORE, "NDStore.edf")
        tables[0].rows[0]["Text"] = "a considerably longer replacement"
        rebuilt = build_var_tables(tables)
        self.assertEqual(rebuilt, self._payload(
            [(b"WEAPON", b"WEAPON", b"a considerably longer replacement")]))

    def test_refuses_a_string_that_is_not_one_terminated_run(self):
        # No terminator: re-encoding would silently add one and grow the
        # record by a byte.
        blob = struct.pack("<I", 1) + struct.pack("<i", 0) + b"\x00" * 128 \
            + struct.pack("<I", 5) + b"hello"
        with self.assertRaises(EdfError):
            parse_var_tables(blob, self.STORE, "NDStore.edf")
        # Interior NUL: it would come back truncated at the first one.
        blob = struct.pack("<I", 1) + struct.pack("<i", 0) + b"\x00" * 128 \
            + struct.pack("<I", 6) + b"he\x00lo\x00"
        with self.assertRaises(EdfError):
            parse_var_tables(blob, self.STORE, "NDStore.edf")

    def test_refuses_a_grammar_that_does_not_close(self):
        payload = self._payload([(b"WEAPON", b"WEAPON", b"Buy a sword.")])
        with self.assertRaises(EdfError):
            parse_var_tables(payload + b"\x00\x00\x00\x00",
                             self.STORE, "NDStore.edf")
        with self.assertRaises(EdfError):
            parse_var_tables(payload[:-4], self.STORE, "NDStore.edf")

    def test_refuses_an_impossible_record_count(self):
        with self.assertRaises(EdfError):
            parse_var_tables(struct.pack("<I", 1 << 30), self.LANG, "x.edf")

    def test_csv_round_trip(self):
        # The hop that matters: out to text, back through a frozen grammar,
        # and byte-identical bytes at the end of it.
        payload = self._payload([(b"WEAPON", b"WEAPON", b"Buy a sword."),
                                 (b"POTION", b"", b"Drink up, \\ friend.")])
        tables = parse_var_tables(payload, self.STORE, "NDStore.edf")
        with tempfile.TemporaryDirectory() as tmp:
            csv_path = os.path.join(tmp, "t.csv")
            json_path = os.path.join(tmp, "t.json")
            tables[0].export_csv(csv_path)
            write_grammar_json(tables[0].grammar, json_path,
                               table_name="NDStore.edf#0",
                               source=tables[0].grammar_source)
            grammar, doc = read_grammar_json(json_path)
            self.assertEqual(grammar, self.STORE[0])
            self.assertEqual(doc["fixed_bytes"], 132)
            self.assertEqual(doc["variable_fields"], 1)
            rebuilt = VarTable.from_csv(csv_path, grammar)
        self.assertEqual(build_var_tables([rebuilt]), payload)

    def test_csv_rejects_reordered_columns(self):
        payload = self._payload([(b"WEAPON", b"WEAPON", b"Buy a sword.")])
        tables = parse_var_tables(payload, self.STORE, "NDStore.edf")
        with tempfile.TemporaryDirectory() as tmp:
            csv_path = os.path.join(tmp, "t.csv")
            tables[0].export_csv(csv_path)
            with open(csv_path, encoding="ascii") as f:
                lines = f.read().splitlines()
            lines[0] = "Name1,Id,Name2,Text"
            with open(csv_path, "w", encoding="ascii", newline="\n") as f:
                f.write("\n".join(lines) + "\n")
            with self.assertRaises(ValueError):
                VarTable.from_csv(csv_path, self.STORE[0])

    def test_grammar_json_catches_a_hand_edit(self):
        with tempfile.TemporaryDirectory() as tmp:
            json_path = os.path.join(tmp, "t.json")
            write_grammar_json(self.STORE[0], json_path)
            with open(json_path, encoding="ascii") as f:
                doc = json.load(f)
            doc["fields"][1]["type"] = "zstr[32]"      # size no longer matches
            with open(json_path, "w", encoding="ascii", newline="\n") as f:
                json.dump(doc, f)
            with self.assertRaises(EdfError):
                read_grammar_json(json_path)

    def test_verify_grammar_rejects_what_cannot_become_a_csv(self):
        with self.assertRaises(EdfError):
            verify_grammar([])
        with self.assertRaises(EdfError):
            verify_grammar([("Name", "zstr[8]"), ("Name", "dword")])
        with self.assertRaises(SchemaError):
            verify_grammar([("Name", "notatype")])

    def test_registry_covers_only_what_is_proven(self):
        self.assertIsNotNone(grammar_for("NDLanguage.edf"))
        self.assertIsNotNone(grammar_for(r"DataTable\en-ph\NDStore.edf"))
        self.assertIsNotNone(grammar_for("Hint.edf"))
        self.assertIsNotNone(grammar_for("UIHelp.edf"))
        self.assertIsNotNone(grammar_for("NDItem.edf"))
        self.assertIsNotNone(grammar_for("NDMsgMonster.edf"))
        # Everything else is still an opaque blob, and must stay one until
        # its grammar is derived rather than guessed.
        self.assertIsNone(grammar_for("Item.edf"))
        self.assertIsNone(grammar_for("NDMap.edf"))
        for name, grammars in EDF_TABLE_GRAMMARS.items():
            for grammar in grammars:
                verify_grammar(grammar, name)

    def test_nditem_grammar_is_two_runs_of_equal_length(self):
        """The 45 = 45 symmetry is what makes NDItem.edf's walk a derivation.

        Nothing in that file states 45; it is what the walk reaches twice,
        independently, reading two different record shapes. If a future edit
        changed one run's length without the other's, the reading would no
        longer be cross-checked by anything -- so the shape is asserted here
        rather than left to the round-trip alone.
        """
        grammars = EDF_TABLE_GRAMMARS["nditem.edf"]
        self.assertEqual(len(grammars), 91)
        names = [g for g in grammars if g == [("Name", "zstr[64]")]]
        descs = [g for g in grammars
                 if g == [("Id", "dword"), ("Unknown1", "dword"),
                          ("Text", LPSTR)]]
        self.assertEqual(len(names), 45)
        self.assertEqual(len(descs), 45)
        self.assertEqual(grammars[:45], names)      # the runs are contiguous
        self.assertEqual(grammars[45:90], descs)    # and in this order
        # The 91st table's 60 fixed bytes are 15 dwords -- the point the
        # earlier reading got wrong by taking them for a variable-length list.
        tail = grammars[90]
        self.assertEqual(sum(1 for _, t in tail if t == "dword"), 16)
        self.assertEqual(tail[1], ("Code", "zstr[4]"))
        self.assertEqual(tail[-1], ("Text", LPSTR))

    def test_nditem_tail_record_round_trips(self):
        """One record of the 91st table, built by hand and read back."""
        grammar = EDF_TABLE_GRAMMARS["nditem.edf"][90]
        text = b"Defeat Splinter Rex" + bytes(1)
        payload = (struct.pack("<I", 1)
                   + struct.pack("<i", 0) + b"a1" + bytes(2)
                   + struct.pack("<15I", *range(15))
                   + struct.pack("<I", len(text)) + text)
        tables = parse_var_tables(payload, [grammar], "NDItem.edf")
        row = tables[0].rows[0]
        self.assertEqual(row["Code"], "a1")
        self.assertEqual(row["Text"], "Defeat Splinter Rex")
        self.assertEqual(row["Unknown15"], 14)
        self.assertEqual(build_var_tables(tables), payload)

    def test_nditem_tail_rejects_a_code_that_is_too_long(self):
        """`a100` fills the 4-byte code exactly; a fifth byte must not fit."""
        grammar = EDF_TABLE_GRAMMARS["nditem.edf"][90]
        table = VarTable(grammar, [dict(
            [("Id", 0), ("Code", "a1000"), ("Text", "x")]
            + [("Unknown%d" % i, 0) for i in range(1, 16)])],
            source="NDItem.edf")
        with self.assertRaises(EdfError):
            table.to_bytes()

    def test_language_grammar_round_trips(self):
        payload = struct.pack("<I", 3)
        for i, text in enumerate([b"Bellato", b"Cora", b"Accretia"]):
            payload += (struct.pack("<i", i)
                        + struct.pack("<I", len(text) + 1) + text + b"\x00")
        tables = parse_var_tables(payload, self.LANG, "NDLanguage.edf")
        self.assertEqual([r["Text"] for r in tables[0].rows],
                         ["Bellato", "Cora", "Accretia"])
        self.assertEqual(build_var_tables(tables), payload)


class BlockRecordTests(unittest.TestCase):
    """BACKLOG #52: records that nest a second, separately counted list.

    The grammar under test is the real `Hint.edf` one -- a fixed header, a
    `<u8>` count of text runs, and runs of fixed bytes plus a `<u16 len>`
    string -- because it exercises both new pieces at once.
    """

    HINT = EDF_TABLE_GRAMMARS["hint.edf"]
    G = HINT[0]

    def _block(self, hint_id, runs):
        out = (struct.pack("<i", hint_id) + bytes((0, 0x32, 0xFF))
               + struct.pack("<III", 0, 15000, 1) + struct.pack("<B", len(runs)))
        for colour, text in runs:
            out += (bytes((0x20, 7)) + struct.pack("<H", 0xCDCD) + colour
                    + struct.pack("<i", -1)
                    + struct.pack("<H", len(text)) + text)
        return out

    def _payload(self, blocks):
        out = struct.pack("<I", len(blocks))
        for hint_id, runs in blocks:
            out += self._block(hint_id, runs)
        return out

    WHITE = b"\xff\xff\xff\xff"
    GREEN = b"\x00\xff\x00\xff"

    def test_round_trip(self):
        payload = self._payload([
            (10, [(self.WHITE, b"To control camera view, "),
                  (self.GREEN, b"click mouse right button")]),
            (20, [(self.WHITE, b"To zoom, use the wheel.")]),
        ])
        tables = parse_var_tables(payload, self.HINT, "Hint.edf")
        self.assertEqual(len(tables), 1)
        self.assertIsInstance(tables[0], BlockTable)
        self.assertEqual([r["Id"] for r in tables[0].rows], [10, 20])
        self.assertEqual([len(g) for g in tables[0].items], [2, 1])
        self.assertEqual(tables[0].rows[0]["Duration"], 15000)
        self.assertEqual(tables[0].items[0][1]["Text"], "click mouse right button")
        self.assertEqual(tables[0].items[0][1]["ColorG"], 0xFF)
        self.assertEqual(build_var_tables(tables), payload)

    def test_item_count_is_derived_not_stored(self):
        # It is not a column, so a hand edit cannot leave it disagreeing with
        # the rows -- and disagreeing here does not truncate one string, it
        # moves every byte in the rest of the table.
        self.assertNotIn("Count", [n for n, _ in self.G.block])
        payload = self._payload([(10, [(self.WHITE, b"one")])])
        tables = parse_var_tables(payload, self.HINT, "Hint.edf")
        tables[0].items[0].append(dict(tables[0].items[0][0], Text="two"))
        self.assertEqual(build_var_tables(tables), self._payload(
            [(10, [(self.WHITE, b"one"), (self.WHITE, b"two")])]))

    def test_wpstr_length_is_derived_and_carries_any_byte(self):
        payload = self._payload([(10, [(self.WHITE, b"short")])])
        tables = parse_var_tables(payload, self.HINT, "Hint.edf")
        tables[0].items[0][0]["Text"] = "a considerably longer replacement"
        self.assertEqual(build_var_tables(tables), self._payload(
            [(10, [(self.WHITE, b"a considerably longer replacement")])]))
        # Unlike LPSTR there is no terminator, so a NUL is data, not a
        # boundary, and has to survive the trip.
        odd = self._payload([(10, [(self.WHITE, b"a\x00b\xa1\xaf")])])
        tables = parse_var_tables(odd, self.HINT, "Hint.edf")
        self.assertEqual(build_var_tables(tables), odd)

    def test_refuses_a_string_longer_than_its_prefix(self):
        payload = self._payload([(10, [(self.WHITE, b"x")])])
        tables = parse_var_tables(payload, self.HINT, "Hint.edf")
        tables[0].items[0][0]["Text"] = "x" * (MAX_WPSTR + 1)
        with self.assertRaises(EdfError):
            build_var_tables(tables)

    def test_refuses_a_grammar_that_does_not_close(self):
        payload = self._payload([(10, [(self.WHITE, b"x")])])
        with self.assertRaises(EdfError):
            parse_var_tables(payload + b"\x00", self.HINT, "Hint.edf")
        with self.assertRaises(EdfError):
            parse_var_tables(payload[:-1], self.HINT, "Hint.edf")

    def test_csv_round_trip_writes_blocks_and_items(self):
        payload = self._payload([
            (10, [(self.WHITE, b"To control camera view, "),
                  (self.GREEN, b"click, \\ then move.")]),
            (-1, []),
            (20, [(self.WHITE, b"To zoom, use the wheel.")]),
        ])
        tables = parse_var_tables(payload, self.HINT, "Hint.edf")
        with tempfile.TemporaryDirectory() as tmp:
            csv_path = os.path.join(tmp, "t.csv")
            json_path = os.path.join(tmp, "t.json")
            tables[0].export_csv(csv_path)
            items_path = BlockTable.items_path(csv_path)
            self.assertTrue(os.path.exists(items_path))
            with open(items_path, encoding="ascii") as f:
                head = f.read().splitlines()
            self.assertEqual(head[0].split(",")[0], "Block")
            # A block with no items contributes no item rows, and still comes
            # back as a block.
            self.assertEqual([line.split(",")[0] for line in head[1:]],
                             ["0", "0", "2"])
            write_grammar_json(tables[0].grammar, json_path,
                               table_name="Hint.edf#0",
                               source=tables[0].grammar_source)
            grammar, doc = read_grammar_json(json_path)
            self.assertEqual(grammar, self.G)
            self.assertEqual(doc["kind"], "block")
            self.assertEqual(doc["item_count_type"], "ubyte")
            self.assertEqual(doc["fixed_bytes"], 19)
            self.assertEqual(doc["item_fixed_bytes"], 12)
            self.assertEqual(doc["item_variable_fields"], 1)
            rebuilt = BlockTable.from_csv(csv_path, grammar)
        self.assertEqual([len(g) for g in rebuilt.items], [2, 0, 1])
        self.assertEqual(build_var_tables([rebuilt]), payload)

    def _export(self, tmp, payload):
        tables = parse_var_tables(payload, self.HINT, "Hint.edf")
        csv_path = os.path.join(tmp, "t.csv")
        tables[0].export_csv(csv_path)
        return csv_path, BlockTable.items_path(csv_path)

    def _rewrite(self, path, edit):
        with open(path, encoding="ascii") as f:
            lines = f.read().splitlines()
        with open(path, "w", encoding="ascii", newline="\n") as f:
            f.write("\n".join(edit(lines)) + "\n")

    def test_items_csv_rejects_a_block_that_is_not_there(self):
        payload = self._payload([(10, [(self.WHITE, b"x")])])
        with tempfile.TemporaryDirectory() as tmp:
            csv_path, items_path = self._export(tmp, payload)
            self._rewrite(items_path,
                          lambda ls: [ls[0], "7" + ls[1][1:]])
            with self.assertRaises(ValueError):
                BlockTable.from_csv(csv_path, self.G)

    def test_items_csv_rejects_rows_out_of_block_order(self):
        # Order inside a block is byte order; reshuffling the file quietly
        # would reshuffle the payload.
        payload = self._payload([(10, [(self.WHITE, b"x")]),
                                 (20, [(self.WHITE, b"y")])])
        with tempfile.TemporaryDirectory() as tmp:
            csv_path, items_path = self._export(tmp, payload)
            self._rewrite(items_path, lambda ls: [ls[0], ls[2], ls[1]])
            with self.assertRaises(ValueError):
                BlockTable.from_csv(csv_path, self.G)

    def test_verify_grammar_rejects_a_block_grammar_that_cannot_work(self):
        with self.assertRaises(EdfError):        # count too wide to be one
            verify_grammar(BlockGrammar([("A", "dword")], "qword",
                                        [("B", "dword")]))
        with self.assertRaises(EdfError):        # Block is the join column
            verify_grammar(BlockGrammar([("A", "dword")], "ubyte",
                                        [("Block", "dword")]))
        with self.assertRaises(EdfError):        # no item fields at all
            verify_grammar(BlockGrammar([("A", "dword")], "ubyte", []))
        verify_grammar(BlockGrammar([("A", "dword")], "ubyte",
                                    [("Text", WPSTR)]))

    def test_grammar_json_catches_a_hand_edit_to_the_item_side(self):
        with tempfile.TemporaryDirectory() as tmp:
            json_path = os.path.join(tmp, "t.json")
            write_grammar_json(self.G, json_path)
            with open(json_path, encoding="ascii") as f:
                doc = json.load(f)
            doc["item_fields"][0]["type"] = "udword"   # 1 byte becomes 4
            with open(json_path, "w", encoding="ascii", newline="\n") as f:
                json.dump(doc, f)
            with self.assertRaises(EdfError):
                read_grammar_json(json_path)

    def test_uihelp_is_the_same_table_repeated(self):
        # 55 tables end to end and no count in front of them: the number of
        # them is what the walk proves, so it has to stay a list of that many
        # identical grammars rather than a single one.
        grammars = grammar_for("UIHelp.edf")
        self.assertEqual(len(grammars), 55)
        self.assertEqual(len(set(id(g) for g in grammars)), 1)
        self.assertIsInstance(grammars[0], BlockGrammar)


class PooledStringTests(unittest.TestCase):
    """BACKLOG #52: fixed records whose text lives in a pool after them.

    The grammar under test is the real `NDMsgMonster.edf` one -- an `Id`,
    twenty `<u32>` length slots, a `<u32>` count of how many are used, and the
    strings themselves end to end after the last record.
    """

    MONSTER = EDF_TABLE_GRAMMARS["ndmsgmonster.edf"]
    G = MONSTER[0]

    def _payload(self, records, slots=None, rec_size=None):
        """`records` is a list of (id, [text, ...])."""
        g = self.G
        slots = g.slots if slots is None else slots
        if rec_size is None:
            rec_size = pool_record_size(g)
        out = struct.pack(CHAIN_HEADER, len(records), rec_size)
        pool = b""
        for rec_id, texts in records:
            lens = [len(t) + 1 for t in texts]
            lens += [0] * (slots - len(lens))
            out += struct.pack("<i", rec_id)
            out += struct.pack("<%dI" % slots, *lens)
            out += struct.pack("<I", len(texts))
            pool += b"".join(t + b"\x00" for t in texts)
        return out + pool

    def test_round_trip(self):
        payload = self._payload([
            (0, []),
            (1, [b"Krr! Scratch you...", b"Oh mommy... ", b"Don't hit me!"]),
            (2, [b"For Crawler Kingdom!"]),
        ])
        tables = parse_var_tables(payload, self.MONSTER, "NDMsgMonster.edf")
        self.assertEqual(len(tables), 1)
        self.assertIsInstance(tables[0], PoolTable)
        self.assertEqual([r["Id"] for r in tables[0].rows], [0, 1, 2])
        self.assertEqual([len(g) for g in tables[0].items], [0, 3, 1])
        self.assertEqual(tables[0].items[1][1]["Text"], "Oh mommy... ")
        self.assertEqual(build_var_tables(tables), payload)

    def test_the_strings_are_one_pool_after_every_record(self):
        # The shape's whole point: a record's text is not next to the record.
        # If it were, this payload and a BlockTable's would be the same bytes.
        payload = self._payload([(0, [b"aa"]), (1, [b"bb"])])
        self.assertTrue(payload.endswith(b"aa\x00bb\x00"))
        tables = parse_var_tables(payload, self.MONSTER, "NDMsgMonster.edf")
        self.assertEqual(tables[0].items[0][0]["Text"], "aa")
        self.assertEqual(tables[0].items[1][0]["Text"], "bb")

    def test_lengths_and_count_are_derived_not_stored(self):
        # Neither is a column, so no hand edit can leave them disagreeing with
        # the text -- and disagreeing here does not truncate one string, it
        # moves every byte of the pool after it.
        self.assertEqual([n for n, _ in self.G.lead], ["Id"])
        payload = self._payload([(7, [b"one"])])
        tables = parse_var_tables(payload, self.MONSTER, "NDMsgMonster.edf")
        tables[0].items[0][0]["Text"] = "a considerably longer replacement"
        tables[0].items[0].append({"Text": "two"})
        self.assertEqual(
            build_var_tables(tables),
            self._payload([(7, [b"a considerably longer replacement",
                                b"two"])]))

    def test_refuses_a_record_size_the_header_disagrees_with(self):
        # The count-only formats have nothing to check a grammar against.
        # This one states its record size, so a grammar that does not add up
        # to it is wrong about the file.
        payload = self._payload([(0, [b"x"])], rec_size=84)
        with self.assertRaises(EdfError):
            parse_var_tables(payload, self.MONSTER, "NDMsgMonster.edf")

    def test_refuses_a_used_slot_past_the_count(self):
        # A value in a slot the record says it does not use means the array is
        # something other than lengths, and everything after it is wrong.
        payload = bytearray(self._payload([(0, [b"x"])]))
        struct.pack_into("<I", payload, CHAIN_HEADER_SIZE + 4 + 4, 9)
        with self.assertRaises(EdfError):
            parse_var_tables(bytes(payload), self.MONSTER, "NDMsgMonster.edf")

    def test_refuses_a_string_that_is_not_one_terminated_run(self):
        payload = bytearray(self._payload([(0, [b"abc"])]))
        payload[-1] = ord("d")                      # terminator gone
        with self.assertRaises(EdfError):
            parse_var_tables(bytes(payload), self.MONSTER, "NDMsgMonster.edf")
        payload = bytearray(self._payload([(0, [b"abc"])]))
        payload[-2] = 0                             # NUL inside the run
        with self.assertRaises(EdfError):
            parse_var_tables(bytes(payload), self.MONSTER, "NDMsgMonster.edf")

    def test_refuses_a_grammar_that_does_not_close(self):
        payload = self._payload([(0, [b"x"])])
        with self.assertRaises(EdfError):
            parse_var_tables(payload + b"\x00", self.MONSTER,
                             "NDMsgMonster.edf")
        with self.assertRaises(EdfError):
            parse_var_tables(payload[:-1], self.MONSTER, "NDMsgMonster.edf")

    def test_refuses_more_strings_than_the_record_has_slots(self):
        payload = self._payload([(0, [b"x"])])
        tables = parse_var_tables(payload, self.MONSTER, "NDMsgMonster.edf")
        tables[0].items[0] = [{"Text": "x"}] * (self.G.slots + 1)
        with self.assertRaises(EdfError):
            build_var_tables(tables)

    def test_csv_round_trip_writes_records_and_strings(self):
        payload = self._payload([(0, []),
                                 (1, [b"first", b"second"]),
                                 (2, [b"third"])])
        tables = parse_var_tables(payload, self.MONSTER, "NDMsgMonster.edf")
        with tempfile.TemporaryDirectory() as tmp:
            csv_path = os.path.join(tmp, "t.csv")
            tables[0].export_csv(csv_path)
            with open(PoolTable.items_path(csv_path), encoding="ascii") as f:
                lines = f.read().splitlines()
            self.assertEqual(lines[0], "Block,Text")
            self.assertEqual(lines[1:], ["1,first", "1,second", "2,third"])
            back = PoolTable.from_csv(csv_path, self.G)
            self.assertEqual(back.to_bytes(), payload)

    def test_items_csv_rejects_rows_out_of_record_order(self):
        payload = self._payload([(0, [b"x"]), (1, [b"y"])])
        tables = parse_var_tables(payload, self.MONSTER, "NDMsgMonster.edf")
        with tempfile.TemporaryDirectory() as tmp:
            csv_path = os.path.join(tmp, "t.csv")
            tables[0].export_csv(csv_path)
            ipath = PoolTable.items_path(csv_path)
            with open(ipath, encoding="ascii") as f:
                lines = f.read().splitlines()
            with open(ipath, "w", encoding="ascii", newline="\n") as f:
                f.write("\n".join([lines[0], lines[2], lines[1]]) + "\n")
            with self.assertRaises(ValueError):
                PoolTable.from_csv(csv_path, self.G)

    def test_verify_grammar_rejects_a_pool_grammar_that_cannot_work(self):
        good = dict(lead=[("Id", "dword")], slot_type="udword", slots=20,
                    count="udword", item="Text")
        with self.assertRaises(EdfError):        # slot too wide to be a length
            verify_grammar(PoolGrammar(**dict(good, slot_type="qword")))
        with self.assertRaises(EdfError):        # no slots to point with
            verify_grammar(PoolGrammar(**dict(good, slots=0)))
        with self.assertRaises(EdfError):        # Block is the join column
            verify_grammar(PoolGrammar(**dict(good, item="Block")))
        with self.assertRaises(EdfError):        # record would not be fixed
            verify_grammar(PoolGrammar(**dict(
                good, lead=[("Id", "dword"), ("Name", LPSTR)])))
        verify_grammar(PoolGrammar(**good))

    def test_grammar_json_catches_a_hand_edit(self):
        with tempfile.TemporaryDirectory() as tmp:
            json_path = os.path.join(tmp, "t.json")
            write_grammar_json(self.G, json_path)
            grammar, doc = read_grammar_json(json_path)
            self.assertEqual(grammar, self.G)
            self.assertEqual(doc["record_bytes"], pool_record_size(self.G))
            doc["slots"] = 19            # 88-byte record becomes 84
            with open(json_path, "w", encoding="ascii", newline="\n") as f:
                json.dump(doc, f)
            with self.assertRaises(EdfError):
                read_grammar_json(json_path)


if __name__ == "__main__":
    unittest.main()
