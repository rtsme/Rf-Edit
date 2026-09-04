"""Unit tests for rf_repo.py's build/status handling of files an install
lacks entirely (BACKLOG #79), manifest entries with no repo copy (#84's
ServerState.ini case), the credential filter that keeps secrets out of
git (#107), and the client root's .edf conversion (#100).

These build synthetic repo/server_root pairs directly -- no real client or
server install needed.

Run:  python -m unittest test_rf_repo -v
"""
import json
import os
import struct
import tempfile
import unittest
import unittest.mock

import rf_edf
import rf_repo
from rf_dat import SchemaError
from rf_repo import Status, build_to_server, diff_repo, sha_bytes


def _write(path, data=b""):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)


def _make_repo(tmp, files, state=()):
    """A minimal repo (no tables) with one files/ entry per (rel, blob).

    `state` names keys (a subset of `files`) that go into manifest["state"]
    -- the BACKLOG #85 runtime-state category.
    """
    repo = os.path.join(tmp, "repo")
    server_root = os.path.join(tmp, "server")
    os.makedirs(repo)
    os.makedirs(server_root)
    manifest_files = {}
    for rel, blob in files.items():
        if blob is not None:
            _write(os.path.join(repo, "files", rel), blob)
            manifest_files[rel] = {"sha": sha_bytes(blob), "bytes": len(blob)}
        else:
            # A manifest entry with no repo/files/ copy (the ServerState.ini
            # shape): tracked, but nothing was ever captured for it.
            manifest_files[rel] = {"sha": "0" * 64, "bytes": 0}
    import json
    with open(os.path.join(repo, "rfrepo.json"), "w") as f:
        json.dump({"server_root": server_root, "tables": {},
                   "files": manifest_files, "secrets": {},
                   "state": sorted(state)}, f)
    return repo, server_root


class BuildCreateTests(unittest.TestCase):
    def test_confirm_alone_never_creates(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo, server_root = _make_repo(tmp, {"Map/a.txt": b"hello"})
            pending, backup = build_to_server(repo, server_root, apply=True)
            self.assertEqual(pending, [])
            self.assertIsNone(backup)
            self.assertFalse(
                os.path.exists(os.path.join(server_root, "Map", "a.txt")))

    def test_allow_create_places_missing_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo, server_root = _make_repo(tmp, {"Map/a.txt": b"hello"})
            pending, backup = build_to_server(repo, server_root, apply=True,
                                              allow_create=True)
            self.assertEqual(len(pending), 1)
            self.assertEqual(pending[0].state, Status.GONE)
            live = os.path.join(server_root, "Map", "a.txt")
            with open(live, "rb") as f:
                self.assertEqual(f.read(), b"hello")

    def test_allow_create_creates_missing_parent_directories(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo, server_root = _make_repo(
                tmp, {"Map/NeutralA/spawn.txt": b"dummy"})
            build_to_server(repo, server_root, apply=True, allow_create=True)
            live = os.path.join(server_root, "Map", "NeutralA", "spawn.txt")
            self.assertTrue(os.path.exists(live))

    def test_backup_tolerates_nonexistent_original(self):
        # The file legitimately never existed on this install -- the backup
        # step must skip it rather than crash on shutil.copy2.
        with tempfile.TemporaryDirectory() as tmp:
            repo, server_root = _make_repo(tmp, {"Map/a.txt": b"hello"})
            pending, backup = build_to_server(repo, server_root, apply=True,
                                              allow_create=True)
            self.assertTrue(pending)  # would raise before reaching here

    def test_allow_create_does_not_touch_existing_files(self):
        # A live install that already matches the repo is untouched --
        # allow_create only reaches GONE entries, never SAME ones.
        with tempfile.TemporaryDirectory() as tmp:
            repo, server_root = _make_repo(tmp, {"Map/a.txt": b"hello"})
            _write(os.path.join(server_root, "Map", "a.txt"), b"hello")
            pending, backup = build_to_server(repo, server_root, apply=True,
                                              allow_create=True)
            self.assertEqual(pending, [])


class NoRepoStatusTests(unittest.TestCase):
    def test_missing_repo_copy_is_norepo_not_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo, server_root = _make_repo(tmp, {"SystemSave/ServerState.ini": None})
            statuses = diff_repo(repo, server_root)
            self.assertEqual(len(statuses), 1)
            self.assertEqual(statuses[0].state, Status.NOREPO)

    def test_norepo_entry_does_not_block_build_of_others(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo, server_root = _make_repo(tmp, {
                "SystemSave/ServerState.ini": None,   # no repo copy
                "Map/a.txt": b"new content",
            })
            # This one exists on the install with different bytes -> CHANGED.
            _write(os.path.join(server_root, "Map", "a.txt"), b"old content")

            # Previously this whole call raised SchemaError because the
            # missing-repo-copy entry counted as ERROR/"broken".
            pending, backup = build_to_server(repo, server_root, apply=True)
            self.assertEqual(len(pending), 1)
            self.assertEqual(pending[0].rel, "Map/a.txt")
            with open(os.path.join(server_root, "Map", "a.txt"), "rb") as f:
                self.assertEqual(f.read(), b"new content")

    def test_real_errors_still_block_build(self):
        # A genuine broken entry (ERROR, not NOREPO) must still refuse to
        # write anything -- including files that would otherwise be created.
        # A table manifest entry with no CSV at all reproduces that ERROR
        # without needing a real schema/table fixture.
        import json
        with tempfile.TemporaryDirectory() as tmp:
            repo, server_root = _make_repo(tmp, {"Map/a.txt": b"hello"})
            with open(os.path.join(repo, "rfrepo.json")) as f:
                manifest = json.load(f)
            manifest["tables"]["Bogus/Table.dat"] = {
                "csv_sha": "0" * 64, "dat_sha": "0" * 64}
            with open(os.path.join(repo, "rfrepo.json"), "w") as f:
                json.dump(manifest, f)

            statuses = diff_repo(repo, server_root)
            self.assertTrue(
                any(s.state == Status.ERROR for s in statuses))
            with self.assertRaises(SchemaError):
                build_to_server(repo, server_root, apply=True,
                                allow_create=True)
            self.assertFalse(
                os.path.exists(os.path.join(server_root, "Map", "a.txt")))


class StateFilesTests(unittest.TestCase):
    """BACKLOG #85: manifest["state"] entries (SystemSave/*_Boss.ini) are
    runtime state the running server rewrites on its own -- never compared,
    never overwritten, only seeded onto an install that lacks them entirely.
    """

    def test_state_entry_never_reported_as_changed(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo, server_root = _make_repo(
                tmp, {"SystemSave/Boss1_Boss.ini": b"repo snapshot"},
                state=["SystemSave/Boss1_Boss.ini"])
            _write(os.path.join(server_root, "SystemSave", "Boss1_Boss.ini"),
                  b"live, rewritten by the server, differs from the repo")
            statuses = diff_repo(repo, server_root)
            self.assertEqual(statuses, [])

    def test_seed_state_places_missing_state_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo, server_root = _make_repo(
                tmp, {"SystemSave/Boss1_Boss.ini": b"seed"},
                state=["SystemSave/Boss1_Boss.ini"])
            pending, backup = build_to_server(repo, server_root, apply=True,
                                              seed_state=True)
            self.assertEqual(len(pending), 1)
            self.assertEqual(pending[0].state, Status.GONE)
            live = os.path.join(server_root, "SystemSave", "Boss1_Boss.ini")
            with open(live, "rb") as f:
                self.assertEqual(f.read(), b"seed")

    def test_seed_state_never_overwrites_existing_state_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo, server_root = _make_repo(
                tmp, {"SystemSave/Boss1_Boss.ini": b"seed"},
                state=["SystemSave/Boss1_Boss.ini"])
            live = os.path.join(server_root, "SystemSave", "Boss1_Boss.ini")
            _write(live, b"live boss state, must survive")
            pending, backup = build_to_server(repo, server_root, apply=True,
                                              seed_state=True)
            self.assertEqual(pending, [])
            with open(live, "rb") as f:
                self.assertEqual(f.read(), b"live boss state, must survive")

    def test_allow_create_alone_does_not_seed_state(self):
        # --allow-create must not reach state entries -- only --seed-state
        # does, so the two opt-ins stay independently meaningful.
        with tempfile.TemporaryDirectory() as tmp:
            repo, server_root = _make_repo(
                tmp, {"SystemSave/Boss1_Boss.ini": b"seed"},
                state=["SystemSave/Boss1_Boss.ini"])
            pending, backup = build_to_server(repo, server_root, apply=True,
                                              allow_create=True)
            self.assertEqual(pending, [])
            self.assertFalse(os.path.exists(
                os.path.join(server_root, "SystemSave", "Boss1_Boss.ini")))


if __name__ == "__main__":
    unittest.main()


class SecretFilterTests(unittest.TestCase):
    """BACKLOG #107: find_secrets is what keeps credentials out of git
    (iron rule 12), and until now nothing tested it.

    That gap is the whole finding. #107 was filed believing the filter
    matched credential-looking *key names* only, and so missed a credential
    hiding in a `DBSTR = Provider=...;PWD=...;` **value**. It does not --
    it splits each line on ';' and re-partitions every chunk, exactly so
    connection strings work. But nothing asserted that, so the belief was
    unfalsifiable in either direction. These tests pin the behaviour down.

    Every fixture below is synthetic. Never put a real value here.
    """

    def test_connection_string_pwd_is_caught(self):
        # The #107 case: the key is DBSTR -- not a credential word -- and the
        # credential is inside the value. This must still be flagged.
        blob = b"[ODBC]\r\nDBSTR = Provider=MSDASQL;DSN=EXAMPLE;UID=someuser;PWD=synthetic-not-real;\r\n"
        keys = [k for k, _v in rf_repo.find_secrets(blob)]
        self.assertIn("pwd", keys)

    def test_connection_string_value_is_returned_for_reporting(self):
        # status/create report what they excluded so a spot-check is possible
        # (spec 02 section 3), which means the value comes back with the key.
        found = rf_repo.find_secrets(
            b"DBSTR = Provider=MSDASQL;DSN=EXAMPLE;PWD=synthetic-not-real;\r\n")
        self.assertEqual(found, [("pwd", "synthetic-not-real")])

    def test_empty_pwd_is_not_a_secret(self):
        # The real rfacc.ini shape on this server: the connection string names
        # a DSN and leaves UID/PWD empty, because the credentials live in the
        # ODBC DSN itself, not in the ini. Such a file carries no secret and
        # is correctly tracked -- flagging it would be a false positive.
        blob = b"[ODBC]\r\nDBSTR = Provider=MSDASQL;DSN=EXAMPLE;UID=;PWD=;\r\nErrDBSTR=\r\nLogLevel=1\r\n"
        self.assertEqual(rf_repo.find_secrets(blob), [])

    def test_underscore_key_is_caught_without_word_boundary(self):
        # The real key on this server is "DB_Password": there is no word
        # boundary between '_' and 'P', so a \b-anchored regex missed it.
        # Substring matching is deliberate; this is that regression.
        keys = [k for k, _v in rf_repo.find_secrets(b"DB_Password=synthetic\r\n")]
        self.assertIn("db_password", keys)

    def test_comment_lines_are_ignored(self):
        # A commented-out example line is documentation, not a leak.
        self.assertEqual(rf_repo.find_secrets(b"; PWD=example\r\n# password=example\r\n"), [])

    def test_placeholder_values_are_not_secrets(self):
        # "MentalPass = TRUE" is a game setting whose key contains "pass".
        # Placeholder values keep it from being reported as a credential.
        self.assertEqual(rf_repo.find_secrets(b"MentalPass = TRUE\r\nOtherPass = 0\r\n"), [])

    def test_uid_alone_is_deliberately_not_a_secret_word(self):
        # SECRET_WORDS matches substrings of the key, and "guid" contains
        # "uid" -- adding "uid" would flag every config file carrying a GUID.
        # A username on its own is not the credential, and a connection string
        # holding a real UID essentially always holds a real PWD too, which is
        # what actually triggers exclusion. This documents the tradeoff so it
        # is a decision rather than an oversight.
        self.assertEqual(rf_repo.find_secrets(b"GUID=1234-5678\r\nUID=someuser\r\n"), [])

    def test_export_files_excludes_a_connection_string_credential(self):
        # End to end: the file lands in `secrets`, which is what puts it in
        # .gitignore and keeps it out of the repo -- while staying on disk.
        with tempfile.TemporaryDirectory() as tmp:
            repo = os.path.join(tmp, "repo")
            server_root = os.path.join(tmp, "server")
            os.makedirs(repo)
            _write(os.path.join(server_root, "RF_Bin", "creds.ini"),
                   b"DBSTR = Provider=MSDASQL;DSN=EXAMPLE;PWD=synthetic-not-real;\r\n")
            _write(os.path.join(server_root, "RF_Bin", "clean.ini"),
                   b"DBSTR = Provider=MSDASQL;DSN=EXAMPLE;UID=;PWD=;\r\n")
            files, secrets = rf_repo.export_files(
                server_root, repo,
                find_fn=lambda r: ["RF_Bin/creds.ini", "RF_Bin/clean.ini"])
            self.assertEqual(sorted(secrets), ["RF_Bin/creds.ini"])
            self.assertEqual(secrets["RF_Bin/creds.ini"], ["pwd"])
            # Both are still captured on disk under files/ -- exclusion is
            # from git, not from the build (spec 02 section 3).
            self.assertIn("RF_Bin/clean.ini", files)
            self.assertTrue(os.path.exists(
                os.path.join(repo, "files", "RF_Bin", "creds.ini")))


class EdfRootTests(unittest.TestCase):
    """BACKLOG #100: the client root converts .edf the way the server root
    converts .dat -- create writes CSVs, status diffs tables, build rebuilds
    the container byte-exactly.

    Every fixture is a synthetic chain-format .edf built here, so these run
    with no client install present. The real 32 files are proved separately,
    by `rf_edf.py --check-tables` and by the scratch build in #100's PR.
    """

    KEY = bytes(range(256))

    @staticmethod
    def _edf(rows=4, key=None):
        """A minimal chain .edf: one table of `rows` two-dword records."""
        payload = (struct.pack("<2I", rows, 8)
                   + b"".join(struct.pack("<2i", i, i * 2)
                              for i in range(rows)))
        return rf_edf.encrypt(payload, key or EdfRootTests.KEY)

    @staticmethod
    def _find_all(root):
        out = []
        for dirpath, _dirs, files in os.walk(root):
            for fn in files:
                out.append(os.path.relpath(os.path.join(dirpath, fn), root))
        return sorted(out)

    def _create(self, tmp, files):
        server_root = os.path.join(tmp, "client")
        for rel, blob in files.items():
            _write(os.path.join(server_root, rel.replace("/", os.sep)), blob)
        repo = os.path.join(tmp, "repo")
        manifest, _tables, skipped = rf_repo.create_repo(
            server_root, repo, convert=False, convert_edf=True,
            find_fn=self._find_all,
            gitattributes=rf_repo.CLIENT_GITATTRIBUTES)
        return repo, server_root, manifest, skipped

    def _edit_first_record(self, repo):
        path = os.path.join(repo, "csv", "DataTable", "Thing.edf", "00.csv")
        with open(path, "r", encoding="ascii") as f:
            lines = f.read().splitlines()
        lines[1] = "999,0"
        with open(path, "w", encoding="ascii", newline="\n") as f:
            f.write("\n".join(lines) + "\n")

    def test_create_writes_one_csv_per_table_and_a_manifest_entry(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo, _root, manifest, skipped = self._create(
                tmp, {"DataTable/Thing.edf": self._edf()})
            self.assertEqual(skipped, [])
            entry = manifest["edf"]["DataTable/Thing.edf"]
            self.assertEqual(
                (entry["kind"], entry["tables"], entry["records"]),
                ("chain", 1, 4))
            for path in (("csv", "DataTable", "Thing.edf", "00.csv"),
                         ("schemas", "DataTable", "Thing.edf", "00.json"),
                         ("schemas", "DataTable", "Thing.edf",
                          rf_repo.EDF_META)):
                self.assertTrue(os.path.exists(os.path.join(repo, *path)),
                                "/".join(path))

    def test_a_converted_edf_is_not_also_copied_verbatim(self):
        # Two copies of the same data in one repo disagree the moment one
        # side is edited (spec 02 section 5). The .ini beside it still is one.
        with tempfile.TemporaryDirectory() as tmp:
            repo, _root, manifest, _skipped = self._create(
                tmp, {"DataTable/Thing.edf": self._edf(),
                      "System/other.ini": b"a=1\r\n"})
            self.assertNotIn("DataTable/Thing.edf", manifest["files"])
            self.assertIn("System/other.ini", manifest["files"])
            self.assertFalse(os.path.exists(os.path.join(
                repo, "files", "DataTable", "Thing.edf")))

    def test_an_edf_that_does_not_convert_stays_a_verbatim_blob(self):
        # Verbatim is a supported end state, not a failure (spec 02 section
        # 6): a file the codec cannot read must still reach the repo, or a
        # clean clone could no longer rebuild a complete install.
        opaque = rf_edf.encrypt(b"\xff" * 32, self.KEY)
        with tempfile.TemporaryDirectory() as tmp:
            repo, _root, manifest, skipped = self._create(
                tmp, {"DataTable/Opaque.edf": opaque})
            self.assertEqual(manifest["edf"], {})
            self.assertEqual([rel.replace(os.sep, "/")
                              for rel, _why in skipped],
                             ["DataTable/Opaque.edf"])
            self.assertIn("DataTable/Opaque.edf", manifest["files"])
            with open(os.path.join(repo, "files", "DataTable",
                                   "Opaque.edf"), "rb") as f:
                self.assertEqual(f.read(), opaque)

    def test_an_edf_that_does_not_rebuild_is_rejected_and_cleaned_up(self):
        # create's promise is that a file only enters the repo once its CSVs
        # have been read back and rebuilt into the original bytes. The only
        # way to reach that check is to make the rebuild wrong, so inject a
        # codec fault: the entry must be dropped, its half-written directories
        # removed, and the file left verbatim instead.
        with tempfile.TemporaryDirectory() as tmp:
            with unittest.mock.patch.object(
                    rf_repo.rf_edf, "build_payload",
                    lambda kind, tables: b"wrong"):
                repo, _root, manifest, skipped = self._create(
                    tmp, {"DataTable/Thing.edf": self._edf()})
            self.assertEqual(manifest["edf"], {})
            self.assertEqual([why for _rel, why in skipped],
                             ["CSV does not rebuild to the original bytes"])
            self.assertFalse(os.path.exists(
                os.path.join(repo, "csv", "DataTable", "Thing.edf")))
            self.assertFalse(os.path.exists(
                os.path.join(repo, "schemas", "DataTable", "Thing.edf")))
            self.assertIn("DataTable/Thing.edf", manifest["files"])

    def test_build_reproduces_the_container_byte_for_byte(self):
        # Only possible because create froze the key: it travels inside the
        # file, and the install is emptied here before the rebuild.
        with tempfile.TemporaryDirectory() as tmp:
            blob = self._edf()
            repo, server_root, _m, _s = self._create(
                tmp, {"DataTable/Thing.edf": blob})
            live = os.path.join(server_root, "DataTable", "Thing.edf")
            os.remove(live)
            pending, _backup = build_to_server(repo, server_root, apply=True,
                                               allow_create=True)
            self.assertEqual([s.rel for s in pending],
                             ["DataTable/Thing.edf"])
            with open(live, "rb") as f:
                self.assertEqual(f.read(), blob)

    def test_status_is_same_when_nothing_moved(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo, server_root, _m, _s = self._create(
                tmp, {"DataTable/Thing.edf": self._edf()})
            states = {s.rel: s.state for s in diff_repo(repo, server_root)}
            self.assertEqual(states["DataTable/Thing.edf"], Status.SAME)

    def test_an_edited_csv_is_reported_per_table(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo, server_root, _m, _s = self._create(
                tmp, {"DataTable/Thing.edf": self._edf()})
            self._edit_first_record(repo)
            s = next(s for s in diff_repo(repo, server_root)
                     if s.rel == "DataTable/Thing.edf")
            self.assertEqual(s.state, Status.CHANGED)
            self.assertEqual(s.kind, Status.EDF)
            self.assertIn("table 0: 1 record(s) changed", s.detail)

    def test_build_writes_the_edit_back_and_status_agrees_again(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo, server_root, _m, _s = self._create(
                tmp, {"DataTable/Thing.edf": self._edf()})
            self._edit_first_record(repo)
            build_to_server(repo, server_root, apply=True)
            live = os.path.join(server_root, "DataTable", "Thing.edf")
            _payload, _key, kind, tables = rf_edf.read_tables(live)
            self.assertEqual(kind, "chain")
            self.assertEqual(tables[0].rows[0]["Index"], 999)
            states = {s.rel: s.state for s in diff_repo(repo, server_root)}
            self.assertEqual(states["DataTable/Thing.edf"], Status.SAME)

    def test_a_missing_layout_blocks_the_whole_build(self):
        # A payload is its tables laid end to end, so losing 00.json would
        # move every table after it: refuse rather than write a
        # plausible-looking wrong .edf.
        with tempfile.TemporaryDirectory() as tmp:
            repo, server_root, _m, _s = self._create(
                tmp, {"DataTable/Thing.edf": self._edf(),
                      "System/other.ini": b"a=1\r\n"})
            os.remove(os.path.join(repo, "schemas", "DataTable", "Thing.edf",
                                   "00.json"))
            _write(os.path.join(server_root, "System", "other.ini"), b"b=2\r\n")
            s = next(s for s in diff_repo(repo, server_root)
                     if s.rel == "DataTable/Thing.edf")
            self.assertEqual(s.state, Status.ERROR)
            with self.assertRaises(SchemaError):
                build_to_server(repo, server_root, apply=True)
            # Nothing was written -- not even the unrelated .ini that differs.
            with open(os.path.join(server_root, "System", "other.ini"),
                      "rb") as f:
                self.assertEqual(f.read(), b"b=2\r\n")

    def test_a_key_that_is_not_a_key_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo, server_root, _m, _s = self._create(
                tmp, {"DataTable/Thing.edf": self._edf()})
            meta = os.path.join(repo, "schemas", "DataTable", "Thing.edf",
                                rf_repo.EDF_META)
            with open(meta, "r", encoding="ascii") as f:
                doc = json.load(f)
            doc["key"] = doc["key"][:-2]
            with open(meta, "w", encoding="ascii", newline="\n") as f:
                json.dump(doc, f)
            s = next(s for s in diff_repo(repo, server_root)
                     if s.rel == "DataTable/Thing.edf")
            self.assertEqual(s.state, Status.ERROR)
            self.assertIn("key is", s.detail)

    def test_a_deleted_csv_is_noticed_by_the_repo_digest(self):
        # repo_sha covers every member by name, so removing one changes it
        # and status re-reads instead of trusting the manifest.
        with tempfile.TemporaryDirectory() as tmp:
            repo, _root, manifest, _s = self._create(
                tmp, {"DataTable/Thing.edf": self._edf()})
            before = manifest["edf"]["DataTable/Thing.edf"]["repo_sha"]
            os.remove(os.path.join(repo, "csv", "DataTable", "Thing.edf",
                                   "00.csv"))
            self.assertNotEqual(
                rf_repo.edf_repo_sha(repo, "DataTable/Thing.edf"), before)

    def test_sync_files_does_not_drag_a_converted_edf_back_in(self):
        # sync-files rewrites files/ from the install. Without the skip it
        # would re-add every .edf as a second, verbatim copy of csv/.
        with tempfile.TemporaryDirectory() as tmp:
            repo, server_root, _m, _s = self._create(
                tmp, {"DataTable/Thing.edf": self._edf(),
                      "System/other.ini": b"a=1\r\n"})
            files, _secrets = rf_repo.sync_files(repo, server_root)
            self.assertNotIn("DataTable/Thing.edf", files)
            self.assertIn("System/other.ini", files)


if __name__ == "__main__":
    unittest.main()
