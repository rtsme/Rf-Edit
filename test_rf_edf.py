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

from rf_dat import SchemaError, Table, infer_schema, write_schema_json
from rf_edf import (CHAIN_HEADER, CHAIN_HEADER_SIZE, DAT_HEADER, EDF_MIN_TEXT_SHARE,
                    EDF_STRING_WIDTHS, EDF_TABLE_GRAMMARS, KEY_LENGTH, MAGIC,
                    LPSTR, MAX_WPSTR, POOLSTR, WPSTR, BYTE_LENGTH, SAME_COUNT,
                    BlockGrammar,
                    BlockTable, ChainGrammar, ChainTable, CompanionRuns,
                    EdfError, GroupGrammar, GroupTable,
                    NestGrammar, NestRun, NestTable, PoolGrammar,
                    PoolTable,
                    VarTable, build_dat_tables, build_table_chain,
                    build_var_tables, chain_layout, chain_record_size,
                    classify, companion_reader, companion_sizes, dat_layout,
                    decrypt, encrypt, field_width, grammar_for, parse_dat_tables,
                    parse_table_chain, parse_var_tables, pool_record_size,
                    INFERRED_CHAIN,
                    read_field, read_grammar_json, verify_grammar,
                    write_field, write_grammar_json,
                    STAMP_HEADER, STAMP_MAGIC, StampTable, build_stamped_tables,
                    parse_stamped_tables, read_stamp_json, stamp_layout,
                    write_stamp_json)


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
        self.assertIsNotNone(grammar_for("NDQuest.edf"))
        self.assertIsNotNone(grammar_for("GameData.edf"))
        self.assertIsNotNone(grammar_for("NDEventShip.edf"))
        self.assertIsNotNone(grammar_for("Resource.edf"))
        self.assertIsNotNone(grammar_for("Map.edf"))
        self.assertIsNotNone(grammar_for("NDMap.edf"))
        # Everything else is still an opaque blob, and must stay one until
        # its grammar is derived rather than guessed.
        self.assertIsNone(grammar_for("Item.edf"))
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


class PooledFieldTests(unittest.TestCase):
    """BACKLOG #52: a pooled string that is one field of a fixed record.

    The grammar under test is the real `NDQuest.edf` one -- a chain table of
    32-byte names, then a chain table of `<u32 Id><u32 0><u32 len><u32 0>`
    whose text sits in a pool behind the records rather than inside them.

    The difference from PooledStringTests is the whole reason this kind
    exists: there a record has a *list* of strings and needs a second CSV,
    here a string is one field the record always has, so it is one column.
    """

    QUEST = EDF_TABLE_GRAMMARS["ndquest.edf"]
    NAMES, TEXTS = QUEST[0], QUEST[1]

    def _names(self, names):
        out = struct.pack(CHAIN_HEADER, len(names), 32)
        return out + b"".join(n.ljust(32, b"\x00") for n in names)

    def _texts(self, records, rec_size=None):
        """`records` is a list of (id, text)."""
        if rec_size is None:
            rec_size = chain_record_size(self.TEXTS)
        out = struct.pack(CHAIN_HEADER, len(records), rec_size)
        pool = b""
        for rec_id, text in records:
            out += struct.pack("<4I", rec_id, 0, len(text) + 1, 0)
            pool += text + b"\x00"
        return out + pool

    def _payload(self, names, records):
        return self._names(names) + self._texts(records)

    def test_round_trip(self):
        payload = self._payload(
            [b"Flym Guard armor", b"WarBeast horn"],
            [(0, b"The weapon was given out"), (1, b"Bring me five horns.")])
        tables = parse_var_tables(payload, self.QUEST, "NDQuest.edf")
        self.assertEqual(len(tables), 2)
        self.assertIsInstance(tables[0], ChainTable)
        self.assertIsInstance(tables[1], ChainTable)
        self.assertEqual([r["Name"] for r in tables[0].rows],
                         ["Flym Guard armor", "WarBeast horn"])
        self.assertEqual(tables[1].rows[1]["Text"], "Bring me five horns.")
        self.assertEqual(build_var_tables(tables), payload)

    def test_a_pooled_field_is_one_column_not_a_second_file(self):
        # The point of the kind. One row per record, columns in record order,
        # and the text in the column its field occupies.
        payload = self._payload([b"a"], [(0, b"hello"), (1, b"there")])
        tables = parse_var_tables(payload, self.QUEST, "NDQuest.edf")
        with tempfile.TemporaryDirectory() as tmp:
            csv_path = os.path.join(tmp, "t.csv")
            tables[1].export_csv(csv_path)
            self.assertFalse(os.path.exists(
                os.path.join(tmp, "t.items.csv")))
            with open(csv_path, encoding="ascii") as f:
                lines = f.read().splitlines()
            self.assertEqual(lines[0], "Id,Unknown1,Text,Unknown2")
            self.assertEqual(lines[1:], ["0,0,hello,0", "1,0,there,0"])
            back = ChainTable.from_csv(csv_path, self.TEXTS)
            self.assertEqual(back.to_bytes(), self._texts(
                [(0, b"hello"), (1, b"there")]))

    def test_the_text_is_behind_the_records_not_inside_them(self):
        # If it were inside, this payload and a VarTable's would be the same
        # bytes. Both strings sit after both records.
        payload = self._texts([(0, b"aa"), (1, b"bb")])
        self.assertTrue(payload.endswith(b"aa" + b"\x00" + b"bb" + b"\x00"))
        self.assertEqual(len(payload),
                         CHAIN_HEADER_SIZE + 2 * 16 + len(b"aa" + b"\x00") * 2)

    def test_the_length_is_derived_not_stored(self):
        # It is not a column, so no hand edit can leave it disagreeing with
        # its string -- and disagreeing here does not truncate that string, it
        # moves every byte of the pool after it.
        self.assertEqual([n for n, _ in self.TEXTS.fields],
                         ["Id", "Unknown1", "Text", "Unknown2"])
        payload = self._texts([(0, b"one"), (1, b"two")])
        tables = parse_var_tables(self._names([]) + payload, self.QUEST,
                                  "NDQuest.edf")
        tables[1].rows[0]["Text"] = "a considerably longer replacement"
        self.assertEqual(
            build_var_tables(tables),
            self._names([]) + self._texts(
                [(0, b"a considerably longer replacement"), (1, b"two")]))

    def test_refuses_a_record_size_the_header_disagrees_with(self):
        # A chain header states the record size, so a grammar that does not
        # add up to it is wrong about the file, not about a label.
        payload = self._names([]) + self._texts([(0, b"x")], rec_size=12)
        with self.assertRaises(EdfError):
            parse_var_tables(payload, self.QUEST, "NDQuest.edf")

    def test_refuses_a_string_that_is_not_one_terminated_run(self):
        base = self._names([]) + self._texts([(0, b"abc")])
        payload = bytearray(base)
        payload[-1] = ord("d")                      # terminator gone
        with self.assertRaises(EdfError):
            parse_var_tables(bytes(payload), self.QUEST, "NDQuest.edf")
        payload = bytearray(base)
        payload[-2] = 0                             # NUL inside the run
        with self.assertRaises(EdfError):
            parse_var_tables(bytes(payload), self.QUEST, "NDQuest.edf")

    def test_refuses_a_zero_length(self):
        # Not even room for the terminator the length is supposed to count.
        payload = bytearray(self._names([]) + self._texts([(0, b"x")]))
        struct.pack_into("<I", payload, CHAIN_HEADER_SIZE * 2 + 8, 0)
        with self.assertRaises(EdfError):
            parse_var_tables(bytes(payload), self.QUEST, "NDQuest.edf")

    def test_refuses_a_grammar_that_does_not_close(self):
        payload = self._names([b"a"]) + self._texts([(0, b"x")])
        with self.assertRaises(EdfError):
            parse_var_tables(payload + b"\x00", self.QUEST, "NDQuest.edf")
        with self.assertRaises(EdfError):
            parse_var_tables(payload[:-1], self.QUEST, "NDQuest.edf")

    def test_a_table_without_a_pooled_field_reads_no_pool(self):
        # The names table is the same kind with no POOLSTR in it: it must stop
        # on its last record and leave the rest of the payload alone.
        payload = self._payload([b"only"], [(0, b"text")])
        tables = parse_var_tables(payload, self.QUEST, "NDQuest.edf")
        self.assertEqual(tables[0].to_bytes(), self._names([b"only"]))

    def test_a_pooled_field_is_read_by_its_table_not_on_its_own(self):
        # read_field/write_field cannot know where the pool starts, so they
        # refuse loudly rather than reading four bytes of length as text.
        with self.assertRaises(EdfError):
            read_field(b"\x00" * 4, 0, POOLSTR, "somewhere")
        with self.assertRaises(EdfError):
            write_field("text", POOLSTR)

    def test_verify_grammar_rejects_a_chain_grammar_that_cannot_work(self):
        with self.assertRaises(EdfError):        # record would not be fixed
            verify_grammar(ChainGrammar([("Id", "dword"), ("T", LPSTR)]))
        with self.assertRaises(EdfError):        # columns must be distinct
            verify_grammar(ChainGrammar([("Id", "dword"), ("Id", "dword")]))
        verify_grammar(ChainGrammar([("Id", "dword"), ("T", POOLSTR)]))

    def test_a_pooled_length_is_four_fixed_bytes_in_the_record(self):
        # What the record holds is the length; the text is elsewhere. So the
        # field is fixed-width, and the record size the header states adds up.
        self.assertEqual(chain_record_size(self.TEXTS), 16)
        self.assertEqual(chain_record_size(self.NAMES), 32)

    def test_csv_rejects_reordered_columns(self):
        payload = self._names([]) + self._texts([(0, b"x")])
        tables = parse_var_tables(payload, self.QUEST, "NDQuest.edf")
        with tempfile.TemporaryDirectory() as tmp:
            csv_path = os.path.join(tmp, "t.csv")
            tables[1].export_csv(csv_path)
            with open(csv_path, encoding="ascii") as f:
                lines = f.read().splitlines()
            with open(csv_path, "w", encoding="ascii", newline="\n") as f:
                f.write("Id,Text,Unknown1,Unknown2\n" + lines[1] + "\n")
            with self.assertRaises(ValueError):
                ChainTable.from_csv(csv_path, self.TEXTS)

    def test_grammar_json_catches_a_hand_edit(self):
        with tempfile.TemporaryDirectory() as tmp:
            json_path = os.path.join(tmp, "t.json")
            write_grammar_json(self.TEXTS, json_path)
            grammar, doc = read_grammar_json(json_path)
            self.assertEqual(grammar, self.TEXTS)
            self.assertEqual(doc["kind"], "chain")
            self.assertEqual(doc["record_bytes"], 16)
            doc["record_bytes"] = 20
            with open(json_path, "w", encoding="ascii", newline="\n") as f:
                json.dump(doc, f)
            with self.assertRaises(EdfError):
                read_grammar_json(json_path)


class MixedChainTests(unittest.TestCase):
    """BACKLOG #52: a file that is chain-shaped in part and not in the rest.

    The grammar under test is the real `NDEventShip.edf` one -- four ordinary
    chain tables read by inference (INFERRED_CHAIN), then one count-only table
    of `<u32 len><len bytes><i32 -1>` messages. `GameData.edf` is the same
    shape with eight chain tables in front instead of four.

    One count-only table at the end is enough to stop `parse_table_chain` at
    offset 0, because the chain walk is all-or-nothing; INFERRED_CHAIN is how
    the tables that *are* chain tables keep being read as such.
    """

    SHIP = EDF_TABLE_GRAMMARS["ndeventship.edf"]
    MESSAGES = SHIP[-1]

    def _chain(self, records, rec_size):
        return (struct.pack(CHAIN_HEADER, len(records), rec_size)
                + b"".join(r.ljust(rec_size, b"\x00") for r in records))

    def _messages(self, texts):
        out = struct.pack("<I", len(texts))
        for text in texts:
            out += struct.pack("<I", len(text) + 1) + text + b"\x00"
            out += struct.pack("<i", -1)
        return out

    def _payload(self, texts=(b"Now boarding.",)):
        return (self._chain([b"Bellato HQ Port of Arrival"], 64)
                + self._chain([b"Cora HQ Port of Arrival"], 64)
                + self._chain([b"Accretia HQ Port of Arrival"], 64)
                + self._chain([struct.pack("<5I", 1, 2, 3, 4, 5)], 20)
                + self._messages(list(texts)))

    def test_round_trip(self):
        payload = self._payload([b"Now boarding.", b"Please buy a ticket."])
        tables = parse_var_tables(payload, self.SHIP, "NDEventShip.edf")
        self.assertEqual(len(tables), 5)
        for table in tables[:4]:
            self.assertIsInstance(table, Table)
        self.assertIsInstance(tables[4], VarTable)
        self.assertEqual([r["Text"] for r in tables[4].rows],
                         ["Now boarding.", "Please buy a ticket."])
        self.assertEqual(build_var_tables(tables), payload)

    def test_a_chain_table_keeps_its_own_eight_byte_header(self):
        # rf_dat.Table.to_bytes writes the server's 12-byte header. A chain
        # table does not carry the middle field_count, so build_var_tables has
        # to write the 8-byte one -- if it did not, every table after the
        # first would move by four bytes.
        payload = self._payload()
        tables = parse_var_tables(payload, self.SHIP, "NDEventShip.edf")
        rebuilt = build_var_tables(tables)
        self.assertEqual(rebuilt[:CHAIN_HEADER_SIZE],
                         struct.pack(CHAIN_HEADER, 1, 64))
        self.assertEqual(len(rebuilt), len(payload))

    def test_an_inferred_chain_table_is_read_by_inference(self):
        # No hand-written field list anywhere: the header states the record
        # size, and the schema is whatever infer_schema makes of the records,
        # under exactly the settings the 17 chain files are read with.
        record = b"Bellato HQ Port of Arrival".ljust(64, bytes([0]))
        tables = parse_var_tables(self._payload(), self.SHIP,
                                  "NDEventShip.edf")
        self.assertEqual(tables[0].rec_size, 64)
        self.assertEqual(tables[0].schema_source, "inferred from records")
        self.assertEqual(tables[0].schema,
                         infer_schema([record], 64,
                                      string_widths=EDF_STRING_WIDTHS,
                                      allow_short_numbers=True,
                                      min_text_share=EDF_MIN_TEXT_SHARE))

    def test_the_message_length_is_derived_not_stored(self):
        # LPSTR's contract, so the CSV holds the text and never a byte count.
        payload = self._payload([b"Now boarding."])
        tables = parse_var_tables(payload, self.SHIP, "NDEventShip.edf")
        self.assertEqual([n for n, _ in tables[4].grammar],
                         ["Text", "Unknown1"])
        tables[4].rows[0]["Text"] = "Now boarding, at last."
        self.assertEqual(build_var_tables(tables),
                         self._payload([b"Now boarding, at last."]))

    def test_refuses_a_grammar_that_does_not_close(self):
        # The count-only table is last, so a message run that stops short
        # leaves bytes over -- which is what a misread count looks like.
        payload = self._payload() + b"\x00\x00\x00\x00"
        with self.assertRaises(EdfError):
            parse_var_tables(payload, self.SHIP, "NDEventShip.edf")

    def test_refuses_a_message_that_is_not_one_terminated_run(self):
        payload = bytearray(self._payload([b"Now boarding."]))
        payload[-5] = 0x21          # the terminator, overwritten
        with self.assertRaises(EdfError):
            parse_var_tables(bytes(payload), self.SHIP, "NDEventShip.edf")

    def test_refuses_a_header_that_is_not_a_table_header(self):
        # An INFERRED_CHAIN table gets chain_layout's guard rails, for
        # chain_layout's reason: a garbage record size is a misread header.
        payload = struct.pack(CHAIN_HEADER, 1, 0) + self._payload()
        with self.assertRaises(EdfError):
            parse_var_tables(payload, [INFERRED_CHAIN] + list(self.SHIP),
                             "NDEventShip.edf")

    def test_refuses_a_chain_table_running_past_the_payload(self):
        payload = struct.pack(CHAIN_HEADER, 4096, 64) + b"\x00" * 16
        with self.assertRaises(EdfError):
            parse_var_tables(payload, [INFERRED_CHAIN], "NDEventShip.edf")

    def test_gamedata_is_the_same_shape_with_more_chain_tables(self):
        gamedata = EDF_TABLE_GRAMMARS["gamedata.edf"]
        self.assertEqual(gamedata[:8], [INFERRED_CHAIN] * 8)
        # The message table is the same one, not a second reading of it: the
        # two files carry the same 61 announcements.
        self.assertEqual(gamedata[-1], self.MESSAGES)

    def test_verify_grammar_accepts_the_sentinel(self):
        self.assertIs(verify_grammar(INFERRED_CHAIN), INFERRED_CHAIN)


class AssetManifestTests(unittest.TestCase):
    """BACKLOG #52: `Resource.edf`, 27 count-only tables of fixed records.

    The grammars under test are the real ones. They need no machinery of their
    own -- flat fixed fields in a count-only table is what `VarTable` already
    is -- so what these cover is the shape: three record sizes the file does
    not state, repeating nine times, one cycle per asset family.
    """

    RESOURCE = EDF_TABLE_GRAMMARS["resource.edf"]
    BONE, MESH, ANI = RESOURCE[0], RESOURCE[1], RESOURCE[2]

    def _table(self, grammar, records):
        out = struct.pack("<I", len(records))
        for rec in records:
            for (name, ftype), value in zip(grammar, rec):
                out += write_field(value, ftype)
        return out

    def test_the_three_record_sizes_are_the_derived_ones(self):
        # 260, 328 and 244 -- what the walk arrives at, and what every one of
        # the 28 011 records in the real file agrees with.
        for grammar, size in ((self.BONE, 260), (self.MESH, 328),
                              (self.ANI, 244)):
            self.assertEqual(sum(field_width(t) for _, t in grammar), size)

    def test_the_cycle_repeats_nine_times(self):
        # Nine asset families, three tables each, and the same three shapes
        # every time -- not 27 independently chosen layouts.
        self.assertEqual(len(self.RESOURCE), 27)
        for i, grammar in enumerate(self.RESOURCE):
            self.assertIs(grammar, self.RESOURCE[i % 3])

    def test_round_trip(self):
        payload = (
            self._table(self.BONE, [
                (0, ".\\CHARACTER\\PLAYER\\BONE\\", "BELMALE.BN",
                 "BELMALE.BBX")])
            + self._table(self.MESH, [
                (4195842, -1, ".\\CHARACTER\\PLAYER\\MESH\\",
                 "ACCRETIA_ARMOR_CLOAK_002.MSH",
                 ".\\CHARACTER\\PLAYER\\TEX\\")])
            + self._table(self.ANI, [
                (16, 1, ".\\CHARACTER\\PLAYER\\ANI\\", "BELMALE_IDLE_00.ANI",
                 3, 11, 19, 23, 0, 0, 0, 0, 0, 0, 0)]))
        tables = parse_var_tables(payload, self.RESOURCE[:3], "Resource.edf")
        self.assertEqual(len(tables), 3)
        self.assertEqual(tables[0].rows[0]["BoundsFile"], "BELMALE.BBX")
        self.assertEqual(tables[1].rows[0]["TexPath"],
                         ".\\CHARACTER\\PLAYER\\TEX\\")
        self.assertEqual(tables[2].rows[0]["AniFile"], "BELMALE_IDLE_00.ANI")
        self.assertEqual(build_var_tables(tables), payload)

    def test_an_empty_table_is_four_bytes(self):
        # Five of the 27 tables are empty in the live file, and an empty table
        # still has to be read: it is what keeps the next count in step.
        payload = self._table(self.BONE, []) + self._table(self.MESH, [])
        tables = parse_var_tables(payload, self.RESOURCE[:2], "Resource.edf")
        self.assertEqual([len(t.rows) for t in tables], [0, 0])
        self.assertEqual(build_var_tables(tables), payload)

    def test_the_animation_count_is_a_column_not_a_derived_number(self):
        # 181 of the 16 976 animation records carry a count of 1 over an array
        # whose first entry is 0. A zero is a value here, so the count must
        # survive the round trip as written rather than be rebuilt from it.
        payload = self._table(self.ANI, [
            (16, 1, ".\\CHARACTER\\NPC\\ANI\\", "NPC_IDLE.ANI",
             1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)])
        tables = parse_var_tables(payload, [self.ANI], "Resource.edf")
        self.assertEqual(tables[0].rows[0]["Unknown2"], 1)
        self.assertEqual(tables[0].rows[0]["Unknown3"], 0)
        self.assertEqual(build_var_tables(tables), payload)

    def test_refuses_a_table_that_runs_past_the_payload(self):
        payload = struct.pack("<I", 4096) + b"\x00" * 260
        with self.assertRaises(EdfError):
            parse_var_tables(payload, [self.BONE], "Resource.edf")

    def test_a_name_may_not_outgrow_its_slot(self):
        # zstr[64] is a fixed slot, so an over-long name is an error rather
        # than a truncation -- every byte after it would move.
        payload = self._table(self.BONE, [
            (0, ".\\CHARACTER\\PLAYER\\BONE\\", "BELMALE.BN", "X.BBX")])
        tables = parse_var_tables(payload, [self.BONE], "Resource.edf")
        tables[0].rows[0]["BoneFile"] = "B" * 65
        with self.assertRaises(EdfError):
            build_var_tables(tables)

class NestedRunTests(unittest.TestCase):
    """BACKLOG #52: a block with several nested runs, and fields after them.

    Two grammars under test, both the real `Map.edf` ones. The minimap table
    exercises the two new ways a run can state its length that BlockGrammar
    had no room for -- a byte length rather than a record count -- and the map
    block exercises the other, a run that shares the count of the run before
    it, along with block fields that sit *after* every run.
    """

    MAP = EDF_TABLE_GRAMMARS["map.edf"]
    BLOCK = MAP[0]
    MINI = MAP[1]

    # ---- minimaps: <u32 W><u32 H><u32 len><name>, marks, then cells -------

    def _mini(self, w, h, name, marks, cells):
        out = struct.pack("<III", w, h, len(name) + 1) + name + b"\x00"
        out += struct.pack("<I", len(marks))
        for mark in marks:
            out += struct.pack("<4i", *mark)
        out += struct.pack("<I", len(cells) * 3)
        for repeat, value in cells:
            out += struct.pack("<HB", repeat, value)
        return out

    def _minis(self, minis):
        return struct.pack("<I", len(minis)) + b"".join(
            self._mini(*m) for m in minis)

    GRID = [(3, 0), (1, 7), (1, 0)]          # 4 + 2 + 2 = 8 cells

    def test_round_trip(self):
        payload = self._minis([
            (4, 2, b"Cora", [(0x372E01, 1, 2, 5)], self.GRID),
            (4, 2, b"Elan", [], self.GRID),
        ])
        tables = parse_var_tables(payload, [self.MINI], "Map.edf")
        self.assertIsInstance(tables[0], NestTable)
        self.assertEqual([r["Name"] for r in tables[0].rows], ["Cora", "Elan"])
        self.assertEqual([len(g) for g in tables[0].runs[0]], [1, 0])
        self.assertEqual(tables[0].runs[0][0][0]["Y"], 1)
        self.assertEqual(tables[0].runs[1][0][1]["Value"], 7)
        self.assertEqual(build_var_tables(tables), payload)

    def test_the_cells_cover_the_grid(self):
        # What proves the triplet: a run is `Repeat + 1` cells long, and the
        # runs add up to exactly the Width x Height the record states.
        tables = parse_var_tables(
            self._minis([(4, 2, b"Cora", [], self.GRID)]), [self.MINI], "m")
        row, cells = tables[0].rows[0], tables[0].runs[1][0]
        self.assertEqual(sum(c["Repeat"] + 1 for c in cells),
                         row["Width"] * row["Height"])

    def test_the_byte_length_is_derived_not_stored(self):
        # Not a column, so adding a cell row cannot leave a stale length
        # behind -- and a stale one here would move every byte after it.
        self.assertNotIn("Length", [n for n, _ in self.MINI.head])
        tables = parse_var_tables(
            self._minis([(4, 2, b"Cora", [], self.GRID)]), [self.MINI], "m")
        tables[0].runs[1][0].append({"Repeat": 0, "Value": 1})
        self.assertEqual(
            build_var_tables(tables),
            self._minis([(4, 2, b"Cora", [], self.GRID + [(0, 1)])]))

    def test_refuses_a_length_that_is_not_whole_records(self):
        payload = bytearray(self._minis([(4, 2, b"Cora", [], self.GRID)]))
        payload[-10] = 8                      # the <u32 9> in front of the cells
        with self.assertRaises(EdfError):
            parse_var_tables(bytes(payload), [self.MINI], "Map.edf")

    def test_refuses_a_grammar_that_does_not_close(self):
        payload = self._minis([(4, 2, b"Cora", [], self.GRID)]) + b"\x00"
        with self.assertRaises(EdfError):
            parse_var_tables(payload, [self.MINI], "Map.edf")

    # ---- map blocks: one count, two runs, and 19 dwords after them --------

    def _record(self, block, index, name):
        return (struct.pack("<ii", block, index) + b"\x00" * 88
                + struct.pack("<3IB", 0, 0, 0, 0)
                + name + b"\x00" * (128 - len(name))
                + b"\x00" * 3 + b"\x00" * 48)

    def _block(self, block_id, name, records, links, n_areas, passages):
        out = (struct.pack("<i", block_id) + name + b"\x00" * (32 - len(name))
               + b"\x00" * 256 + struct.pack("<HI", 0, len(records)))
        for i, rname in enumerate(records):
            out += self._record(block_id, i, rname)
        for link in links:
            out += struct.pack("<ii", *link)
        out += struct.pack("<I", n_areas) + b"\x00" * (96 * n_areas)
        out += struct.pack("<I", len(passages))
        for index, pname in passages:
            out += (struct.pack("<5i", index, 0, 0, 0, 0)
                    + pname + b"\x00" * (64 - len(pname)))
        return out + struct.pack("<19i", *range(19))

    def _blocks(self, blocks):
        return struct.pack("<I", len(blocks)) + b"".join(
            self._block(*b) for b in blocks)

    def _one(self):
        return self._blocks([
            (0, b"NeutralB", [b"dpgoto_bellato_HQ", b"dpfrom_bl_grsd"],
             [(-1, -1), (25, 1)], 0, [(0, b"Union HQ Portal")]),
        ])

    def test_a_block_reads_its_runs_and_then_its_trailer(self):
        tables = parse_var_tables(self._one(), [self.BLOCK], "Map.edf")
        table = tables[0]
        self.assertEqual(table.rows[0]["Name"], "NeutralB")
        self.assertEqual([n for n, _ in self.BLOCK.runs[0].fields][:2],
                         ["MapIndex", "Index"])
        self.assertEqual(table.runs[0][0][1]["Name"], "dpfrom_bl_grsd")
        self.assertEqual(table.runs[1][0][1], {"ToMap": 25, "ToRecord": 1})
        self.assertEqual(table.runs[2][0], [])
        self.assertEqual(table.runs[3][0][0]["Name"], "Union HQ Portal")
        # The 19 trailing dwords belong to the block, not to any run.
        self.assertEqual(table.rows[0]["Unknown20"], 18)
        self.assertEqual(build_var_tables(tables), self._one())

    def test_the_links_share_the_records_count(self):
        # The file states one number for both arrays, so a links row without a
        # records row has nowhere to be written and is refused rather than
        # silently dropping the rest of the block.
        self.assertEqual(self.BLOCK.runs[1].count, SAME_COUNT)
        tables = parse_var_tables(self._one(), [self.BLOCK], "Map.edf")
        tables[0].runs[1][0].append({"ToMap": -1, "ToRecord": -1})
        with self.assertRaises(EdfError):
            build_var_tables(tables)

    def test_a_block_with_no_records_is_still_a_block(self):
        payload = self._blocks([(0, b"Empty", [], [], 0, [])])
        tables = parse_var_tables(payload, [self.BLOCK], "Map.edf")
        self.assertEqual([len(g) for g in tables[0].runs[0]], [0])
        self.assertEqual(build_var_tables(tables), payload)

    # ---- the CSVs, and the frozen grammar ---------------------------------

    def test_csv_round_trip_writes_one_file_per_run(self):
        payload = self._blocks([
            (0, b"NeutralB", [b"dpgoto_bellato_HQ"], [(-1, -1)], 0,
             [(0, b"Union HQ Portal")]),
            (1, b"Dungeon00", [], [], 0, []),
        ])
        tables = parse_var_tables(payload, [self.BLOCK], "Map.edf")
        with tempfile.TemporaryDirectory() as tmp:
            csv_path = os.path.join(tmp, "t.csv")
            json_path = os.path.join(tmp, "t.json")
            tables[0].export_csv(csv_path)
            for run in ("records", "links", "areas", "passages"):
                self.assertTrue(
                    os.path.exists(NestTable.run_path(csv_path, run)), run)
            with open(NestTable.run_path(csv_path, "records"),
                      encoding="ascii") as f:
                head = f.read().splitlines()
            self.assertEqual(head[0].split(",")[0], "Block")
            self.assertEqual([line.split(",")[0] for line in head[1:]], ["0"])
            # Head and tail fields are one row's worth of facts and share the
            # block CSV, even though runs sit between them in the payload.
            with open(csv_path, encoding="ascii") as f:
                columns = f.read().splitlines()[0].split(",")
            self.assertEqual(columns[0], "Id")
            self.assertEqual(columns[-1], "Unknown20")
            write_grammar_json(tables[0].grammar, json_path,
                               table_name="Map.edf#0",
                               source=tables[0].grammar_source)
            grammar, doc = read_grammar_json(json_path)
            self.assertEqual(grammar, self.BLOCK)
            self.assertEqual(doc["kind"], "nest")
            self.assertEqual([r["name"] for r in doc["runs"]],
                             ["records", "links", "areas", "passages"])
            self.assertEqual([r["count_type"] for r in doc["runs"]],
                             ["udword", SAME_COUNT, "udword", "udword"])
            self.assertEqual(doc["runs"][0]["fixed_bytes"], 288)
            self.assertEqual(doc["tail_fixed_bytes"], 76)
            rebuilt = NestTable.from_csv(csv_path, grammar)
        self.assertEqual(build_var_tables([rebuilt]), payload)

    def test_grammar_json_catches_a_hand_edit_to_a_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "t.json")
            write_grammar_json(self.MINI, path)
            with open(path, encoding="ascii") as f:
                doc = json.load(f)
            doc["runs"][1]["fields"][0]["type"] = "udword"
            with open(path, "w", encoding="ascii", newline="\n") as f:
                json.dump(doc, f)
            with self.assertRaises(EdfError):
                read_grammar_json(path)

    def test_run_csv_rejects_rows_out_of_block_order(self):
        payload = self._blocks([
            (0, b"A", [b"one"], [(-1, -1)], 0, []),
            (1, b"B", [b"two"], [(-1, -1)], 0, []),
        ])
        tables = parse_var_tables(payload, [self.BLOCK], "Map.edf")
        with tempfile.TemporaryDirectory() as tmp:
            csv_path = os.path.join(tmp, "t.csv")
            tables[0].export_csv(csv_path)
            rpath = NestTable.run_path(csv_path, "records")
            with open(rpath, encoding="ascii") as f:
                lines = f.read().splitlines()
            with open(rpath, "w", encoding="ascii", newline="\n") as f:
                f.write("\n".join([lines[0], lines[2], lines[1]]) + "\n")
            with self.assertRaises(ValueError):
                NestTable.from_csv(csv_path, self.BLOCK)

    def test_verify_grammar_rejects_a_nest_grammar_that_cannot_work(self):
        head = [("Id", "dword")]
        run = NestRun("items", "udword", [("Val", "dword")])
        verify_grammar(NestGrammar(head, [run], []))
        with self.assertRaises(SchemaError):          # nothing nested at all
            verify_grammar(NestGrammar(head, [], []))
        with self.assertRaises(SchemaError):          # no run before it
            verify_grammar(NestGrammar(head, [run._replace(count=SAME_COUNT)], []))
        with self.assertRaises(SchemaError):          # two runs, one CSV name
            verify_grammar(NestGrammar(head, [run, run], []))
        with self.assertRaises(SchemaError):          # not a count type
            verify_grammar(NestGrammar(head, [run._replace(count="float")], []))
        with self.assertRaises(SchemaError):          # bytes, but how many?
            verify_grammar(NestGrammar(head, [NestRun(
                "items", BYTE_LENGTH, [("Text", LPSTR)])], []))
        with self.assertRaises(SchemaError):          # that column is the join
            verify_grammar(NestGrammar(head, [NestRun(
                "items", "udword", [("Block", "dword")])], []))
        with self.assertRaises(SchemaError):          # head and tail collide
            verify_grammar(NestGrammar(head, [run], [("Id", "dword")]))

    def test_map_is_one_block_table_and_two_minimap_tables(self):
        # The 31 world minimaps and the 7 world-map insets are the same shape
        # written twice, which is why the file needs no count in front of them.
        self.assertEqual(len(self.MAP), 3)
        self.assertEqual(self.MAP[1], self.MAP[2])
        self.assertEqual([r.name for r in self.BLOCK.runs],
                         ["records", "links", "areas", "passages"])


class GroupedRunTests(unittest.TestCase):
    """BACKLOG #56: groups whose lengths are in a different file.

    `en-ph/NDMap.edf` states how many groups it holds and nothing else -- the
    length of each one is in `Map.edf`. The pair under test here is a
    miniature of that: a companion whose blocks each carry a counted run, and
    a grouped table with one label per mark plus one for the block itself.

    What these check above all is the direction of the dependency. The
    companion is read to *parse* a payload; rebuilding one from CSV must never
    touch it, or an edit to the companion alone would silently move every byte
    of the file that borrows from it.
    """

    COMPANION = NestGrammar(
        [("Id", "dword")],
        [NestRun("marks", "udword", [("X", "dword")])],
        [])
    LABELS = GroupGrammar(CompanionRuns("Atlas.edf", 0, ("marks",), 1),
                          [("Label", LPSTR)])

    def _atlas(self, marks):
        """A companion payload: one block per entry, that many marks in it."""
        out = struct.pack("<I", len(marks))
        for i, n in enumerate(marks):
            out += struct.pack("<II", i, n)
            out += b"".join(struct.pack("<i", 100 + j) for j in range(n))
        return out

    def _companion(self, marks):
        tables = parse_var_tables(self._atlas(marks), [self.COMPANION],
                                  "Atlas.edf")
        return lambda name: tables

    def _labels(self, groups):
        out = struct.pack("<I", len(groups))
        for group in groups:
            for text in group:
                out += struct.pack("<I", len(text) + 1) + text + b"\x00"
        return out

    GROUPS = [[b"Cauldron", b"Abandon Cave", b"Vapor Lake"], [b"Elan", b"Sette"]]
    MARKS = [2, 1]                       # 1 + marks == 3 and 2

    def test_round_trip(self):
        payload = self._labels(self.GROUPS)
        tables = parse_var_tables(payload, [self.LABELS], "NDAtlas.edf",
                                  companion=self._companion(self.MARKS))
        self.assertIsInstance(tables[0], GroupTable)
        self.assertEqual(tables[0].groups, [3, 2])
        self.assertEqual([r["Label"] for r in tables[0].rows],
                         ["Cauldron", "Abandon Cave", "Vapor Lake", "Elan",
                          "Sette"])
        self.assertEqual(build_var_tables(tables), payload)

    def test_the_csv_carries_the_grouping(self):
        # The group number is the only place the split survives, so it has to
        # be in the CSV: the payload does not hold it and the rebuild will not
        # go looking for it.
        tables = parse_var_tables(self._labels(self.GROUPS), [self.LABELS],
                                  "NDAtlas.edf",
                                  companion=self._companion(self.MARKS))
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "labels.csv")
            tables[0].export_csv(path)
            with open(path, encoding="ascii") as f:
                lines = f.read().splitlines()
        self.assertEqual(lines[0], "Block,Label")
        self.assertEqual([line.split(",")[0] for line in lines[1:]],
                         ["0", "0", "0", "1", "1"])

    def test_rebuilding_from_csv_never_reads_the_companion(self):
        """The point of the shape: an edit to `Map.edf` cannot move a byte.

        The rebuild happens here with no companion in reach at all -- if
        `from_csv` needed one it could not run, let alone reproduce the bytes.
        """
        payload = self._labels(self.GROUPS)
        tables = parse_var_tables(payload, [self.LABELS], "NDAtlas.edf",
                                  companion=self._companion(self.MARKS))
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "labels.csv")
            tables[0].export_csv(path)
            rebuilt = GroupTable.from_csv(path, self.LABELS)
        self.assertEqual(rebuilt.groups, [3, 2])
        self.assertEqual(build_var_tables([rebuilt]), payload)

    def test_the_frozen_grammar_carries_the_companion(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "labels.json")
            write_grammar_json(self.LABELS, path, table_name="NDAtlas.edf#0")
            with open(path, encoding="ascii") as f:
                doc = json.load(f)
            self.assertEqual(doc["kind"], "group")
            self.assertEqual(doc["companion"],
                             {"file": "Atlas.edf", "table": 0,
                              "runs": ["marks"], "plus": 0 + 1})
            grammar, _doc = read_grammar_json(path)
        self.assertEqual(grammar, self.LABELS)

    def test_refuses_to_parse_without_a_companion(self):
        # Unreadable on its own is the true statement about such a file, and
        # saying so beats guessing a split that would rebuild corrupted rows.
        with self.assertRaises(EdfError):
            parse_var_tables(self._labels(self.GROUPS), [self.LABELS],
                             "NDAtlas.edf")

    def test_refuses_a_companion_that_describes_a_different_number_of_groups(self):
        with self.assertRaises(EdfError):
            parse_var_tables(self._labels(self.GROUPS), [self.LABELS],
                             "NDAtlas.edf",
                             companion=self._companion([2, 1, 4]))

    def test_refuses_a_split_that_does_not_close(self):
        # A wrong length here does not truncate one record, it moves every
        # byte after it -- so the walk missing the last byte is the check.
        with self.assertRaises(EdfError):
            parse_var_tables(self._labels(self.GROUPS), [self.LABELS],
                             "NDAtlas.edf", companion=self._companion([1, 1]))

    def test_refuses_a_companion_that_measures_an_empty_group(self):
        # An empty group leaves no row to carry its number, so the CSV could
        # not be read back -- it has to fail on the way out, not on the way in.
        spec = self.LABELS.groups._replace(plus=0)
        tables = parse_var_tables(self._atlas([2, 0]), [self.COMPANION], "a")
        with self.assertRaises(EdfError):
            companion_sizes(spec, tables, "NDAtlas.edf#0")

    def test_refuses_a_companion_run_it_does_not_have(self):
        tables = parse_var_tables(self._atlas([2, 1]), [self.COMPANION], "a")
        with self.assertRaises(EdfError):
            companion_sizes(self.LABELS.groups._replace(runs=("cells",)),
                            tables, "NDAtlas.edf#0")
        with self.assertRaises(EdfError):
            companion_sizes(self.LABELS.groups._replace(table=3),
                            tables, "NDAtlas.edf#0")

    def test_a_companion_that_is_not_there_says_so(self):
        read = companion_reader(os.path.join(tempfile.gettempdir(),
                                             "en-ph", "NDAtlas.edf"))
        with self.assertRaises(EdfError):
            read("NoSuchCompanion.edf")

    def test_import_refuses_gapped_or_reordered_groups(self):
        header = "Block,Label\n"
        for body in ("0,a\n2,b\n",           # a gap: group 1 vanished
                     "1,a\n0,b\n",           # out of order
                     "0,a\n1,b\n0,c\n"):    # ungrouped
            with tempfile.TemporaryDirectory() as tmp:
                path = os.path.join(tmp, "labels.csv")
                with open(path, "w", encoding="ascii", newline="") as f:
                    f.write(header + body)
                with self.assertRaises(ValueError):
                    GroupTable.from_csv(path, self.LABELS)

    def test_verify_grammar_refuses_a_grammar_that_cannot_be_measured(self):
        spec = self.LABELS.groups
        with self.assertRaises(EdfError):            # no file named
            verify_grammar(GroupGrammar(spec._replace(file=""),
                                        [("Label", LPSTR)]))
        with self.assertRaises(EdfError):            # no run named
            verify_grammar(GroupGrammar(spec._replace(runs=()),
                                        [("Label", LPSTR)]))
        with self.assertRaises(EdfError):            # not a table index
            verify_grammar(GroupGrammar(spec._replace(table=-1),
                                        [("Label", LPSTR)]))
        with self.assertRaises(EdfError):            # that column is the join
            verify_grammar(GroupGrammar(spec, [("Block", "dword")]))
        with self.assertRaises(EdfError):            # lengths from nowhere
            verify_grammar(GroupGrammar(("Atlas.edf", 0), [("Label", LPSTR)]))

    def test_ndmap_mirrors_map_table_for_table(self):
        """Three tables against `Map.edf`'s three, in the same order.

        `NDMap.edf` states none of its own record counts, so the registry
        entry *is* the reading: if a future edit pointed a table at a
        different companion table or dropped a run from the measure, the walk
        would still close on some other file and the round trip would still
        pass. The mirroring is asserted here instead.
        """
        nd = EDF_TABLE_GRAMMARS["ndmap.edf"]
        self.assertEqual(len(nd), len(EDF_TABLE_GRAMMARS["map.edf"]))
        self.assertEqual([g.groups.table for g in nd], [0, 1, 2])
        self.assertEqual({g.groups.file for g in nd}, {"Map.edf"})
        # a block's names: its own, then one per record, then one per passage
        self.assertEqual(nd[0].groups.runs, ("records", "passages"))
        self.assertEqual(nd[0].groups.plus, 1)
        # a minimap's labels: one per mark. The world grids and the insets are
        # the same shape read twice, differing only in which companion table
        # measures them -- exactly as `Map.edf`'s own two are one grammar
        # written twice.
        self.assertEqual(nd[1], nd[2]._replace(
            groups=nd[2].groups._replace(table=1)))
        self.assertEqual(nd[1].groups.runs, ("marks",))
        self.assertEqual(nd[1].groups.plus, 0)



class StampedPayloadTests(unittest.TestCase):
    """`Item.edf`: a table chain whose tables each carry a 10-byte stamp.

    The stamp states its own offset and its body length, both of which are
    redundant with where the walk already is and with the chain header four
    bytes further on. The refusals below are the point of that redundancy: a
    stamp read at the wrong place has to stop the walk, not half-read it.
    """

    SCHEMA = [("Index", "dword"), ("Code", "string[16]")]
    REC_SIZE = 20

    def _table(self, index, rows, offset):
        body = struct.pack(CHAIN_HEADER, len(rows), self.REC_SIZE)
        for i, code in rows:
            body += struct.pack("<i", i) + code.ljust(16, b"\x00")
        return (struct.pack(STAMP_HEADER, index, STAMP_MAGIC, len(body), offset)
                + body)

    def _footer(self, index, offset, values):
        body = struct.pack("<%dI" % len(values), *values)
        return (struct.pack(STAMP_HEADER, index, STAMP_MAGIC, len(body), offset)
                + body)

    def test_stamped_round_trip(self):
        payload = self._table(0, [(0, b"ACM"), (1, b"ACF")], 0)
        self.assertEqual(stamp_layout(payload), [(0, 48, 0)])
        parsed = parse_stamped_tables(payload, "Item.edf")
        self.assertEqual(len(parsed), 1)
        self.assertEqual(parsed[0].index, 0)
        self.assertTrue(parsed[0].headed)
        self.assertEqual(parsed[0].schema, self.SCHEMA)
        self.assertEqual(parsed[0].rows[1]["Code"], "ACF")
        self.assertEqual(build_stamped_tables(parsed), payload)

    def test_several_blocks_end_to_end(self):
        a = self._table(0, [(0, b"ACM"), (1, b"ACF")], 0)
        b = self._table(1, [(2, b"DEM")], len(a))
        payload = a + b
        self.assertEqual(stamp_layout(payload), [(0, 48, 0), (1, 28, len(a))])
        self.assertEqual(build_stamped_tables(parse_stamped_tables(payload)),
                         payload)

    def test_index_byte_is_carried_not_recomputed(self):
        """`Item.edf` numbers its blocks 0..45 and then 47, skipping 46.

        Nothing in the payload derives that, so a rebuild that renumbered the
        blocks from their position would write a file the client reads
        differently. The stamp's index has to survive the round trip.
        """
        a = self._table(0, [(0, b"ACM")], 0)
        b = self._table(47, [(1, b"ACF")], len(a))
        parsed = parse_stamped_tables(a + b)
        self.assertEqual([t.index for t in parsed], [0, 47])
        self.assertEqual(build_stamped_tables(parsed), a + b)

    def test_a_body_that_is_not_a_chain_table_is_kept_as_dwords(self):
        """The last block's 368 bytes do not satisfy `8 + count * size`.

        Inferring a schema from a single record invents string columns out of
        runs of zero bytes, so the footer is read as numbers instead -- the
        same refusal `_table_from_records` makes for an empty table.
        """
        values = [0, 406, 594, 0, 0, 176]
        payload = self._footer(47, 0, values)
        parsed = parse_stamped_tables(payload, "Item.edf")
        self.assertEqual(len(parsed), 1)
        self.assertFalse(parsed[0].headed)
        self.assertEqual([t for _, t in parsed[0].schema],
                         ["dword"] * len(values))
        self.assertEqual([parsed[0].rows[0]["Val%d" % (i + 1)]
                          for i in range(len(values))], values)
        self.assertEqual(build_stamped_tables(parsed), payload)

    def test_refuses_a_stamp_that_misstates_its_own_offset(self):
        a = self._table(0, [(0, b"ACM")], 0)
        b = self._table(1, [(1, b"ACF")], len(a) + 4)   # wrong own-offset
        with self.assertRaises(EdfError):
            stamp_layout(a + b)

    def test_refuses_a_wrong_magic_byte(self):
        payload = bytearray(self._table(0, [(0, b"ACM")], 0))
        payload[1] = 0xF2
        with self.assertRaises(EdfError):
            stamp_layout(bytes(payload))

    def test_refuses_a_body_running_past_the_end(self):
        payload = self._table(0, [(0, b"ACM"), (1, b"ACF")], 0)
        with self.assertRaises(EdfError):
            stamp_layout(payload[:-1])

    def test_refuses_a_trailing_stub_too_short_for_a_stamp(self):
        payload = self._table(0, [(0, b"ACM")], 0)
        with self.assertRaises(EdfError):
            stamp_layout(payload + bytes(6))

    def test_refuses_an_unheaded_body_that_is_not_whole_dwords(self):
        body = b"\x01\x02\x03"
        payload = (struct.pack(STAMP_HEADER, 0, STAMP_MAGIC, len(body), 0)
                   + body)
        with self.assertRaises(EdfError):
            parse_stamped_tables(payload, "Item.edf")

    def test_a_plain_chain_is_not_read_as_stamped(self):
        """The four readings must not compete for a file.

        A chain payload's first eight bytes are a count and a record size, and
        reading them as a stamp puts the walk somewhere arbitrary -- so this
        has to raise rather than return a plausible layout.
        """
        chain = (struct.pack(CHAIN_HEADER, 1, self.REC_SIZE)
                 + struct.pack("<i", 0) + b"ACM".ljust(16, b"\x00"))
        with self.assertRaises(EdfError):
            stamp_layout(chain)

    def test_stamp_json_round_trips_the_stamp(self):
        parsed = parse_stamped_tables(
            self._table(47, [(0, b"ACM")], 0), "Item.edf")
        with tempfile.TemporaryDirectory() as tmp:
            csv_path = os.path.join(tmp, "00.csv")
            layout = os.path.join(tmp, "00.json")
            parsed[0].export_csv(csv_path)
            write_stamp_json(parsed[0], layout, table_name="Item.edf#0",
                             source="inferred from records")
            schema, doc = read_stamp_json(layout)
            self.assertEqual(doc["stamp_index"], 47)
            self.assertTrue(doc["stamp_headed"])
            back = StampTable.from_csv(csv_path, schema, doc["stamp_index"],
                                       doc["stamp_headed"],
                                       field_count=doc["header_field_count"])
            self.assertEqual(build_stamped_tables([back]),
                             build_stamped_tables(parsed))

    def test_a_schema_json_without_a_stamp_is_refused(self):
        """A plain schema doc must not be usable as a stamped block's layout.

        It would rebuild every block with index 0 and a chain header, which is
        a different file that still looks like a valid one.
        """
        parsed = parse_stamped_tables(
            self._table(0, [(0, b"ACM")], 0), "Item.edf")
        with tempfile.TemporaryDirectory() as tmp:
            layout = os.path.join(tmp, "00.json")
            write_schema_json(parsed[0].schema, layout, dat_name="Item.edf#0")
            with self.assertRaises(EdfError):
                read_stamp_json(layout)


if __name__ == "__main__":
    unittest.main()
