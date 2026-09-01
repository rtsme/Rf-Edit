"""Unit tests for rf_repo.py's build/status handling of files an install
lacks entirely (BACKLOG #79) and manifest entries with no repo copy (#84's
ServerState.ini case).

These build synthetic repo/server_root pairs directly -- no real client or
server install needed.

Run:  python -m unittest test_rf_repo -v
"""
import os
import tempfile
import unittest

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
