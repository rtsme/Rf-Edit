"""Unit tests for rf_repo.py's build/status handling of files an install
lacks entirely (BACKLOG #79), manifest entries with no repo copy (#84's
ServerState.ini case), and the credential filter that keeps secrets out of
git (#107).

These build synthetic repo/server_root pairs directly -- no real client or
server install needed.

Run:  python -m unittest test_rf_repo -v
"""
import os
import tempfile
import unittest

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
