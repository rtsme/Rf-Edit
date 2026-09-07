"""Unit tests for rf_dat.py's Table.open schema-resolution chain -- in
particular the repo-schema fallback added for BACKLOG #26 (a missing/moved
`RF_PARSER_DIR` silently degraded 93 tables to weaker inference and broke
round-trip entirely for two of them, `MonsterCharacter.dat` and `Quest.dat`;
see docs/knowledge/rf-repo-parser-dir-dependency.md).

These build synthetic .dat files and schema JSON directly -- no real server
install or parser export needed.

Run:  python -m unittest test_rf_dat -v
"""
import os
import struct
import tempfile
import unittest

from rf_dat import HEADER_FMT, HEADER_SIZE, Table, encode, write_schema_json

SCHEMA = [("Id", "dword"), ("Name", "string[8]"), ("Val", "dword")]


def _write_dat(path, schema, rows, header_field_count=None):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    rec_size = sum(4 if t != "string[8]" else 8 for _, t in schema)
    field_count = (header_field_count if header_field_count is not None
                   else len(schema))
    with open(path, "wb") as f:
        f.write(struct.pack(HEADER_FMT, len(rows), field_count, rec_size))
        for row in rows:
            for name, ftype in schema:
                f.write(encode(row[name], ftype))


class RepoSchemaFallbackTests(unittest.TestCase):
    def test_used_when_no_txt_export_and_record_size_matches(self):
        with tempfile.TemporaryDirectory() as tmp:
            dat = os.path.join(tmp, "server", "TestTable.dat")
            rows = [{"Id": 1, "Name": "abc", "Val": 7}]
            _write_dat(dat, SCHEMA, rows)

            schema_dir = os.path.join(tmp, "repo", "schemas")
            os.makedirs(schema_dir)
            write_schema_json(SCHEMA, os.path.join(schema_dir, "TestTable.json"),
                              dat_name="TestTable.dat", source="test fixture")

            t = Table.open(dat, parser_dir=os.path.join(tmp, "no-such-parser"),
                           repo_schema_dir=schema_dir)

            self.assertTrue(t.schema_source.endswith("(repo schema)"))
            self.assertEqual(t.schema, SCHEMA)
            self.assertTrue(t.roundtrip_ok())

    def test_ignored_when_record_size_does_not_match(self):
        with tempfile.TemporaryDirectory() as tmp:
            dat = os.path.join(tmp, "server", "TestTable.dat")
            rows = [{"Id": 1, "Name": "abc", "Val": 7}]
            _write_dat(dat, SCHEMA, rows)

            # A schema for a same-named table with a different byte layout --
            # e.g. a stale/incompatible repo checkout. Must not be trusted.
            stale = [("Id", "dword"), ("Val", "dword")]
            schema_dir = os.path.join(tmp, "repo", "schemas")
            os.makedirs(schema_dir)
            write_schema_json(stale, os.path.join(schema_dir, "TestTable.json"),
                              dat_name="TestTable.dat", source="stale fixture")

            t = Table.open(dat, parser_dir=os.path.join(tmp, "no-such-parser"),
                           repo_schema_dir=schema_dir)

            self.assertEqual(t.schema_source, "inferred from records")

    def test_relaxes_field_count_check_like_per_map_tables(self):
        """A repo schema is used even when the header's declared field_count
        disagrees with the schema's true field count -- record_size is what
        matters (per-map tables routinely lie about field_count; see
        verify_schema's docstring)."""
        with tempfile.TemporaryDirectory() as tmp:
            dat = os.path.join(tmp, "server", "TestTable.dat")
            rows = [{"Id": 1, "Name": "abc", "Val": 7}]
            _write_dat(dat, SCHEMA, rows, header_field_count=1)

            schema_dir = os.path.join(tmp, "repo", "schemas")
            os.makedirs(schema_dir)
            write_schema_json(SCHEMA, os.path.join(schema_dir, "TestTable.json"),
                              dat_name="TestTable.dat", source="test fixture")

            t = Table.open(dat, parser_dir=os.path.join(tmp, "no-such-parser"),
                           repo_schema_dir=schema_dir)

            self.assertTrue(t.schema_source.endswith("(repo schema)"))
            self.assertFalse(t.strict_field_count)
            self.assertTrue(t.roundtrip_ok())

    def test_no_match_falls_through_to_inference(self):
        with tempfile.TemporaryDirectory() as tmp:
            dat = os.path.join(tmp, "server", "TestTable.dat")
            rows = [{"Id": 1, "Name": "abc", "Val": 7}]
            _write_dat(dat, SCHEMA, rows)

            empty_schema_dir = os.path.join(tmp, "repo", "schemas")
            os.makedirs(empty_schema_dir)

            t = Table.open(dat, parser_dir=os.path.join(tmp, "no-such-parser"),
                           repo_schema_dir=empty_schema_dir)

            self.assertEqual(t.schema_source, "inferred from records")
            self.assertTrue(t.roundtrip_ok())


if __name__ == "__main__":
    unittest.main()
