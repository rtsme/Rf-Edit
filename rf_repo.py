"""
Keep a whole RF Online server's .dat tables in a git repo as CSV, edit them in
an IDE, and build the changes back into the server.

Library + CLI. The GUI in rf_workbench.py drives the same functions.

    python rf_repo.py create  --server "C:\\...\\1_Server AOP" --repo D:\\rf-data
    python rf_repo.py status  --repo D:\\rf-data
    python rf_repo.py build   --repo D:\\rf-data [--confirm]

The repo mirrors the server's folder structure, so a table that lives in
Zoneserver\\RF_Bin\\Map\\NeutralA on the server is at
csv/Zoneserver/RF_Bin/Map/NeutralA/<name>.csv in the repo, with its schema
beside it under schemas/.

Why the CSVs can be trusted as the source of truth: `create` re-imports every
CSV it writes, rebuilds the .dat, and compares byte-for-byte against the
original before accepting it. A table only enters the repo if that trip is
proven lossless for that exact file. What no check can tell you is whether an
*edit* was correct -- a valid number in the wrong column is still valid -- so
read `status` before you build.
"""
import argparse
import difflib
import fnmatch
import hashlib
import json
import os
import re
import shutil
import sys
import time

from rf_dat import (SchemaError, Table, read_schema_json, record_size,
                    write_schema_json)

MANIFEST = "rfrepo.json"

# Files copied into the repo byte-for-byte instead of being converted. They're
# already text; there is nothing to gain from parsing them and something to
# lose, since rewriting a config file is how you change behaviour by accident.
VERBATIM_EXTS = (".ini",)

# Key names that make a setting a credential. Matched as substrings of the key,
# because the real one on this server is "DB_Password" -- an earlier version of
# this used a \b word boundary and missed it, since there is no boundary
# between "_" and "P". Erring towards false positives is the right direction
# here: a wrongly flagged file is still on disk and still deploys, it just
# isn't committed, and it is reported so you can undo that in one line.
SECRET_WORDS = ("password", "passwd", "pwd", "pass", "secret", "token",
                "apikey", "api_key", "api-key", "credential")
# Values that mean "nothing set here", so "MentalPass = TRUE" and "PWD=;" don't
# get reported as leaked credentials.
SECRET_PLACEHOLDERS = {"", "none", "null", "true", "false", "0", "-1", "x"}

GITIGNORE = """\
# Rebuilt .dat files and deploy backups -- derived, and binaries bloat history.
build/
backups/
*.bak
"""

GITATTRIBUTES = """\
# Everything here is ASCII with LF endings and must stay that way: these tables
# carry game text in a legacy encoding, escaped as \\xNN, and any tool that
# decides to "fix" the encoding or the line endings silently corrupts fields
# nobody edited. The catch-all matters as much as the specific rules -- without
# it, core.autocrlf on a Windows checkout rewrites files it isn't told about.
* text=auto eol=lf
*.csv text eol=lf
*.json text eol=lf
*.md text eol=lf

# files/ holds byte-for-byte copies of the server's own config files, and they
# are NOT uniform: on this server 32 .ini files use CRLF, 58 use LF and one
# mixes both. -text switches off every conversion so a checkout reproduces the
# exact bytes the server had. They still diff as text -- none contain NULs.
files/** -text
"""

README_TEMPLATE = """\
# %(name)s

The `.dat` tables from an RF Online server, as CSV, so they can be diffed,
reviewed and edited in a normal editor instead of a hex editor.

Server this was created from:

    %(server)s

## Layout

- `csv/` mirrors the server's folder structure. One file per table, one line
  per record, first line is the field names.
- `schemas/` the field order and types for each table, frozen here so a
  checkout can rebuild the `.dat` files without any external tooling.
- `%(manifest)s` records the server path and a checksum per table.
- `build/`, `backups/` generated, git-ignored.

## Editing

**Columns are the binary record layout** -- don't add, remove or reorder them.
Rows can be added or removed freely; the rebuilt record count follows the
number of lines.

- Bytes outside printable ASCII are escaped `\\xNN`, mostly the legacy Korean
  text. A literal backslash is `\\\\`. Leave these alone unless you mean to
  change them.
- `-1` is the usual "empty slot" marker.

Strings are capped at their field width and numbers at their type's range;
both are checked on build, with the file, line and column named.

## Building back

    python rf_repo.py status --repo <this folder>
    python rf_repo.py build  --repo <this folder> --confirm

`status` lists which tables would change and by how many records. `build`
backs up every file it overwrites into `backups/<timestamp>/` first.

## Coverage

%(coverage)s
"""


# ---------------------------------------------------------------- scanning

def find_dats(root):
    """Every .dat under root, as paths relative to root."""
    out = []
    for dirpath, _dirs, files in os.walk(root):
        for fn in files:
            if fn.lower().endswith(".dat"):
                out.append(os.path.relpath(os.path.join(dirpath, fn), root))
    return sorted(out)


def find_verbatim(root, exts=VERBATIM_EXTS):
    """Every file under root with a verbatim extension, relative to root."""
    lower = tuple(e.lower() for e in exts)
    out = []
    for dirpath, _dirs, files in os.walk(root):
        for fn in files:
            if fn.lower().endswith(lower):
                out.append(os.path.relpath(os.path.join(dirpath, fn), root))
    return sorted(out)


def find_secrets(blob):
    """Credential-looking assignments in a config file. [(key, value)].

    Parsed rather than regexed, so connection strings work: a line like
    "DBSTR = Provider=MSDASQL;DSN=BILLING;UID=login;PWD=password;" is split on
    ';' first, and each chunk's key is what comes before its first '='.
    """
    out = []
    for raw in blob.splitlines():
        line = raw.decode("latin-1")
        if line.lstrip()[:1] in (";", "#"):        # ini comment
            continue
        for chunk in line.split(";"):
            if "=" not in chunk:
                continue
            key, _sep, value = chunk.partition("=")
            key = key.strip().lower()
            value = value.strip().strip('"\'')
            if not any(w in key for w in SECRET_WORDS):
                continue
            if value.lower() in SECRET_PLACEHOLDERS:
                continue
            out.append((key, value))
    return out


def sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def sha_bytes(blob):
    return hashlib.sha256(blob).hexdigest()


def rel_to_csv(rel):
    return os.path.splitext(rel)[0] + ".csv"


def rel_to_schema(rel):
    return os.path.splitext(rel)[0] + ".json"


def read_manifest(repo):
    path = os.path.join(repo, MANIFEST)
    if not os.path.exists(path):
        raise SchemaError(
            "%s has no %s -- it isn't an rf-data repo (or was made by an "
            "older version)." % (repo, MANIFEST))
    with open(path, "r", encoding="ascii") as f:
        return json.load(f)


def write_manifest(repo, doc):
    with open(os.path.join(repo, MANIFEST), "w", encoding="ascii",
              newline="\n") as f:
        json.dump(doc, f, indent=1, sort_keys=True)
        f.write("\n")


# ------------------------------------------------------------------ create

def create_repo(server_root, repo, progress=None, include=None):
    """Convert every convertible .dat under server_root into repo/csv/.

    Returns (manifest, converted, skipped) where skipped is a list of
    (rel_path, reason) -- tables that could not be represented losslessly and
    were therefore left out rather than half-imported.
    """
    rels = find_dats(server_root)
    if include:
        rels = [r for r in rels
                if any(fnmatch.fnmatch(r.replace("\\", "/"), pat)
                       for pat in include)]
    total = len(rels)
    tables, skipped = {}, []

    for i, rel in enumerate(rels):
        if progress:
            progress(i, total, rel)
        src = os.path.join(server_root, rel)
        try:
            t = Table.open(src)
        except (SchemaError, ValueError, OSError) as e:
            skipped.append((rel, str(e).split("\n")[0]))
            continue
        if not t.roundtrip_ok():
            skipped.append((rel, "does not round-trip; schema is wrong"))
            del t
            continue

        csv_path = os.path.join(repo, "csv", rel_to_csv(rel))
        schema_path = os.path.join(repo, "schemas", rel_to_schema(rel))
        os.makedirs(os.path.dirname(csv_path), exist_ok=True)
        os.makedirs(os.path.dirname(schema_path), exist_ok=True)
        t.export_csv(csv_path)
        write_schema_json(t.schema, schema_path, dat_name=rel,
                          source=t.schema_source,
                          header_field_count=t.field_count)

        # Prove it: rebuild from what we just wrote and compare to the original.
        rebuilt = Table.from_csv(csv_path, t.schema,
                                 field_count=t.field_count).to_bytes()
        with open(src, "rb") as f:
            original = f.read()
        if rebuilt != original:
            os.remove(csv_path)
            os.remove(schema_path)
            skipped.append((rel, "CSV does not rebuild to the original bytes"))
            del t
            continue

        tables[rel.replace("\\", "/")] = {
            "csv_sha": sha(csv_path),
            "dat_sha": sha_bytes(original),
            "records": len(t.rows),
            "schema_source": t.schema_source,
        }
        del t

    if progress:
        progress(total, total, "copying config files")
    files, secrets = export_files(server_root, repo, progress=progress)

    manifest = {
        "server_root": os.path.abspath(server_root),
        "created": time.strftime("%Y-%m-%d %H:%M:%S"),
        "tables": tables,
        "skipped": {rel.replace("\\", "/"): why for rel, why in skipped},
        "files": files,
        "secrets": secrets,
    }
    os.makedirs(repo, exist_ok=True)
    write_manifest(repo, manifest)

    write_repo_meta(repo, server_root, manifest, n_dats=len(rels))
    return manifest, tables, skipped


def write_repo_meta(repo, server_root, manifest, n_dats=None):
    """(Re)write README, .gitignore and .gitattributes from the manifest."""
    tables = manifest.get("tables", {})
    skipped = manifest.get("skipped", {})
    files = manifest.get("files", {})
    secrets = manifest.get("secrets", {})
    if n_dats is None:
        n_dats = len(tables) + len(skipped)
    coverage = (
        "%d of %d .dat files under the server root are in this repo. The other "
        "%d could not be represented losslessly and were left out; see "
        "`skipped` in %s for the reason per file.\n\n"
        "%d config file(s) are copied verbatim, byte for byte, under `files/`. "
        "They are not converted -- they are already text -- so editing one in "
        "the repo and building copies exactly those bytes back to the server."
        % (len(tables), n_dats, len(skipped), MANIFEST, len(files)))
    gitignore = GITIGNORE
    if secrets:
        coverage += (
            "\n\n%d of those config files contain credentials and are listed "
            "in .gitignore, so they stay in your working tree -- editable, and "
            "still built back to the server -- but never enter git history. "
            "The detector errs towards false positives; if one is wrongly "
            "flagged, delete its line from .gitignore." % len(secrets))
        gitignore += (
            "\n# Config files carrying credentials. Still on disk under files/\n"
            "# and still built back to the server -- just kept out of git\n"
            "# history. Generated by rf_repo; remove a line to un-ignore.\n")
        for key in sorted(secrets):
            gitignore += "files/%s\n" % key
    for name, text in ((".gitignore", gitignore),
                       (".gitattributes", GITATTRIBUTES),
                       ("README.md", README_TEMPLATE % {
                           "name": os.path.basename(os.path.abspath(repo)),
                           "server": os.path.abspath(server_root),
                           "manifest": MANIFEST,
                           "coverage": coverage})):
        with open(os.path.join(repo, name), "w", encoding="ascii",
                  newline="\n") as f:
            f.write(text)


def sync_files(repo, server_root=None, exts=VERBATIM_EXTS, progress=None):
    """Refresh only the verbatim files/ tree of an existing repo.

    Lets config files be added to a repo whose tables are already exported,
    without spending twenty minutes reconverting several thousand .dat files
    that haven't changed.
    """
    manifest = read_manifest(repo)
    server_root = server_root or manifest["server_root"]
    files, secrets = export_files(server_root, repo, exts, progress=progress)
    manifest["files"] = files
    manifest["secrets"] = secrets
    write_manifest(repo, manifest)
    write_repo_meta(repo, server_root, manifest)
    return files, secrets


def export_files(server_root, repo, exts=VERBATIM_EXTS, progress=None):
    """Copy the server's config files into repo/files/ byte-for-byte.

    Returns (files, secrets). `secrets` maps a repo-relative path to the
    credential keys found in it; those paths are also written into .gitignore
    so they stay in the working tree -- editable, and buildable back to the
    server -- without ever entering git history.
    """
    rels = find_verbatim(server_root, exts)
    files, secrets = {}, {}
    for i, rel in enumerate(rels):
        if progress:
            progress(i, len(rels), rel)
        src = os.path.join(server_root, rel)
        dst = os.path.join(repo, "files", rel)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        with open(src, "rb") as f:
            blob = f.read()
        with open(dst, "wb") as f:          # binary: no newline translation
            f.write(blob)
        key = rel.replace("\\", "/")
        files[key] = {"sha": sha_bytes(blob), "bytes": len(blob)}
        found = find_secrets(blob)
        if found:
            secrets[key] = sorted({k for k, _v in found})
    return files, secrets


# ------------------------------------------------------------------ status

class Status(object):
    """One table's state: how the repo compares to the server."""

    SAME, CHANGED, GONE, ERROR = "same", "changed", "missing", "error"

    TABLE, FILE = "table", "file"

    def __init__(self, rel, state, detail="", changed_records=None,
                 kind=TABLE):
        self.rel = rel
        self.state = state
        self.detail = detail
        self.changed_records = changed_records or []
        self.kind = kind          # a converted .dat, or a verbatim copy

    def __repr__(self):
        return "<%s %s %s %s>" % (self.kind, self.rel, self.state, self.detail)


def build_table(repo, rel):
    """Rebuild one table from the repo. Returns (Table, bytes)."""
    schema_path = os.path.join(repo, "schemas", rel_to_schema(rel))
    csv_path = os.path.join(repo, "csv", rel_to_csv(rel))
    schema, doc = read_schema_json(schema_path)
    t = Table.from_csv(csv_path, schema,
                       field_count=doc.get("header_field_count"))
    return t, t.to_bytes()


def diff_repo(repo, server_root=None, progress=None):
    """Compare every table in the repo against the server. Returns [Status].

    Tables whose CSV and .dat both still hash to what the manifest recorded are
    reported unchanged without being parsed -- otherwise a preview would mean
    re-reading several thousand files to find the two you edited.
    """
    manifest = read_manifest(repo)
    server_root = server_root or manifest["server_root"]
    rels = sorted(manifest["tables"])
    total = len(rels)
    out = []
    for i, rel in enumerate(rels):
        if progress:
            progress(i, total, rel)
        entry = manifest["tables"][rel]
        native = rel.replace("/", os.sep)
        csv_path = os.path.join(repo, "csv", rel_to_csv(native))
        dat_path = os.path.join(server_root, native)

        if not os.path.exists(csv_path):
            out.append(Status(rel, Status.ERROR, "csv is missing from the repo"))
            continue
        if not os.path.exists(dat_path):
            out.append(Status(rel, Status.GONE, "not on the server"))
            continue

        csv_sha, dat_sha = sha(csv_path), sha(dat_path)
        if csv_sha == entry.get("csv_sha") and dat_sha == entry.get("dat_sha"):
            out.append(Status(rel, Status.SAME))
            continue

        try:
            t, blob = build_table(repo, native)
        except (SchemaError, ValueError, OSError) as e:
            out.append(Status(rel, Status.ERROR, str(e).split("\n")[0]))
            continue
        with open(dat_path, "rb") as f:
            live = f.read()
        if live == blob:
            out.append(Status(rel, Status.SAME))
        else:
            idx, detail = record_delta(live, blob, t.rec_size)
            out.append(Status(rel, Status.CHANGED, detail, idx))
        del t

    out.extend(diff_files(repo, server_root, manifest))
    return out


def diff_files(repo, server_root, manifest):
    """Compare the verbatim copies in repo/files/ against the server.

    A key also listed in manifest["secrets"] is a real credential file
    deliberately left out of repo/files/ (rule 12: secrets never enter git,
    only .example templates are tracked) - it is not a broken table, so it
    is skipped here rather than reported as ERROR and blocking every build.
    """
    out = []
    secrets = manifest.get("secrets", {})
    for key in sorted(manifest.get("files", {})):
        if key in secrets:
            continue
        native = key.replace("/", os.sep)
        repo_path = os.path.join(repo, "files", native)
        live_path = os.path.join(server_root, native)
        if not os.path.exists(repo_path):
            out.append(Status(key, Status.ERROR, "copy is missing from the repo",
                              kind=Status.FILE))
            continue
        if not os.path.exists(live_path):
            out.append(Status(key, Status.GONE, "not on the server",
                              kind=Status.FILE))
            continue
        with open(repo_path, "rb") as f:
            mine = f.read()
        with open(live_path, "rb") as f:
            live = f.read()
        if mine == live:
            out.append(Status(key, Status.SAME, kind=Status.FILE))
        else:
            # difflib works on str, and these files are in a legacy encoding,
            # so compare latin-1 views -- lossless, and only used for counting.
            a = live.decode("latin-1").splitlines()
            b = mine.decode("latin-1").splitlines()
            n = sum(max(i2 - i1, j2 - j1)
                    for tag, i1, i2, j1, j2 in difflib.SequenceMatcher(
                        None, a, b, autojunk=False).get_opcodes()
                    if tag != "equal")
            detail = ("%d line(s) differ" % n if n
                      else "line endings or trailing bytes differ")
            out.append(Status(key, Status.CHANGED, detail, kind=Status.FILE))
    return out


def text_changes(repo, rel, server_root, limit=500):
    """Line-level diff of one verbatim file. [(lineno, tag, server, repo)].

    Decoded as latin-1 purely for display -- it round-trips any byte, so a
    config file in a legacy encoding shows up readably enough to review
    without ever being re-encoded on the way back out.
    """
    native = rel.replace("/", os.sep)
    with open(os.path.join(server_root, native), "rb") as f:
        live = f.read().decode("latin-1").splitlines()
    with open(os.path.join(repo, "files", native), "rb") as f:
        mine = f.read().decode("latin-1").splitlines()
    out = []
    sm = difflib.SequenceMatcher(None, live, mine, autojunk=False)
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == "equal":
            continue
        for k in range(max(i2 - i1, j2 - j1)):
            old = live[i1 + k] if i1 + k < i2 else ""
            new = mine[j1 + k] if j1 + k < j2 else ""
            out.append((i1 + k + 1, tag, old, new))
            if len(out) >= limit:
                return out
    return out


def record_delta(live, blob, rec_size):
    """Which record indices differ between two .dat blobs."""
    from rf_dat import HEADER_SIZE
    n_live = (len(live) - HEADER_SIZE) // rec_size
    n_new = (len(blob) - HEADER_SIZE) // rec_size
    if n_live != n_new:
        return [], "record count %d -> %d" % (n_live, n_new)
    diff = []
    for i in range(n_live):
        s = HEADER_SIZE + i * rec_size
        if live[s:s + rec_size] != blob[s:s + rec_size]:
            diff.append(i)
    return diff, "%d record(s) changed" % len(diff)


def field_changes(repo, rel, server_root, limit=500):
    """Per-field before/after for one table. [(record, field, old, new)]."""
    native = rel.replace("/", os.sep)
    repo_t, _blob = build_table(repo, native)
    live_t = Table.open(os.path.join(server_root, native))
    out = []
    n = min(len(repo_t.rows), len(live_t.rows))
    for i in range(n):
        a, b = live_t.rows[i], repo_t.rows[i]
        for name, _ftype in repo_t.schema:
            if a.get(name) != b.get(name):
                out.append((i, name, a.get(name), b.get(name)))
                if len(out) >= limit:
                    return out, len(repo_t.rows) - len(live_t.rows)
    return out, len(repo_t.rows) - len(live_t.rows)


# ------------------------------------------------------------------- build

def build_to_server(repo, server_root=None, only=None, apply=False,
                    progress=None):
    """Write changed tables back to the server. Returns (written, backup_dir).

    With apply=False nothing is written; the return value is the list that
    *would* be written, which is what the GUI previews.
    """
    manifest = read_manifest(repo)
    server_root = server_root or manifest["server_root"]
    statuses = diff_repo(repo, server_root, progress=progress)
    pending = [s for s in statuses if s.state == Status.CHANGED]
    if only is not None:
        wanted = set(only)
        pending = [s for s in pending if s.rel in wanted]
    broken = [s for s in statuses if s.state == Status.ERROR]
    if broken:
        raise SchemaError(
            "%d table(s) don't build; refusing to write anything:\n%s"
            % (len(broken), "\n".join("  %s: %s" % (s.rel, s.detail)
                                      for s in broken[:10])))
    if not apply or not pending:
        return pending, None

    backup_dir = os.path.join(repo, "backups", time.strftime("%Y%m%d-%H%M%S"))
    for i, s in enumerate(pending):
        if progress:
            progress(i, len(pending), "writing " + s.rel)
        native = s.rel.replace("/", os.sep)
        live_path = os.path.join(server_root, native)
        bak = os.path.join(backup_dir, native)
        os.makedirs(os.path.dirname(bak), exist_ok=True)
        shutil.copy2(live_path, bak)

        if s.kind == Status.FILE:
            # Verbatim: copy the bytes back exactly as they sit in the repo.
            with open(os.path.join(repo, "files", native), "rb") as f:
                blob = f.read()
            with open(live_path, "wb") as f:
                f.write(blob)
            manifest["files"][s.rel]["sha"] = sha_bytes(blob)
            manifest["files"][s.rel]["bytes"] = len(blob)
        else:
            _t, blob = build_table(repo, native)
            with open(live_path, "wb") as f:
                f.write(blob)
            manifest["tables"][s.rel]["dat_sha"] = sha_bytes(blob)
            manifest["tables"][s.rel]["csv_sha"] = sha(
                os.path.join(repo, "csv", rel_to_csv(native)))
    write_manifest(repo, manifest)
    return pending, backup_dir


# --------------------------------------------------------------------- CLI

def _bar(done, total, msg):
    sys.stdout.write("\r  %5d/%-5d %-58s" % (done, total, msg[-58:]))
    sys.stdout.flush()


def cmd_create(args):
    if not args.server:
        raise SystemExit("--server is required for create")
    manifest, tables, skipped = create_repo(args.server, args.repo,
                                            progress=_bar)
    print("\n\ncreated %s" % os.path.abspath(args.repo))
    print("  %d table(s) converted" % len(tables))
    print("  %d skipped" % len(skipped))
    reasons = {}
    for rel, why in skipped:
        reasons.setdefault(why, []).append(rel)
    for why, rels in sorted(reasons.items(), key=lambda kv: -len(kv[1])):
        print("    %5d  %s" % (len(rels), why[:90]))
    return 0


def cmd_sync_files(args):
    files, secrets = sync_files(args.repo, args.server, progress=_bar)
    sys.stdout.write("\r" + " " * 78 + "\r")
    print("%d config file(s) copied into files/" % len(files))
    if secrets:
        print("\n%d contain credentials and were added to .gitignore:"
              % len(secrets))
        for key in sorted(secrets):
            print("  %-56s (%s)" % (key, ", ".join(secrets[key])))
        print("\nThey are still on disk and still build back to the server; "
              "they just won't be committed.")
    return 0


def cmd_status(args):
    statuses = diff_repo(args.repo, args.server, progress=_bar)
    sys.stdout.write("\r" + " " * 78 + "\r")
    changed = [s for s in statuses if s.state == Status.CHANGED]
    broken = [s for s in statuses if s.state == Status.ERROR]
    gone = [s for s in statuses if s.state == Status.GONE]
    if changed:
        print("WOULD CHANGE ON THE SERVER (%d):" % len(changed))
        for s in changed:
            print("  %-58s %s" % (s.rel[-58:], s.detail))
        print()
    if broken:
        print("WON'T BUILD (%d) -- build is blocked until these are fixed:"
              % len(broken))
        for s in broken:
            print("  %-58s %s" % (s.rel[-58:], s.detail[:60]))
        print()
    if gone:
        print("in the repo but not on the server: %d\n" % len(gone))
    print("%d unchanged, %d changed, %d missing, %d broken"
          % (len(statuses) - len(changed) - len(broken) - len(gone),
             len(changed), len(gone), len(broken)))
    return 1 if broken else 0


def cmd_build(args):
    pending, backup = build_to_server(args.repo, args.server,
                                      apply=args.confirm, progress=_bar)
    sys.stdout.write("\r" + " " * 78 + "\r")
    if not pending:
        print("Nothing to build -- the server already matches the repo.")
        return 0
    for s in pending:
        print("  %-58s %s" % (s.rel[-58:], s.detail))
    if args.confirm:
        print("\nWrote %d file(s). Originals backed up to\n  %s"
              % (len(pending), backup))
    else:
        print("\n%d file(s) would change. Nothing written -- re-run with "
              "--confirm to apply." % len(pending))
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--repo", required=True, help="repo directory")
    p.add_argument("--server", default=None,
                   help="server root (defaults to the one recorded in the repo)")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("create", help="server .dat -> new repo").set_defaults(
        func=cmd_create)
    sub.add_parser("sync-files",
                   help="refresh only the verbatim config files (.ini)"
                   ).set_defaults(func=cmd_sync_files)
    sub.add_parser("status", help="what would change on the server").set_defaults(
        func=cmd_status)
    b = sub.add_parser("build", help="write changed tables to the server")
    b.add_argument("--confirm", action="store_true",
                   help="actually write (without it, only lists changes)")
    b.set_defaults(func=cmd_build)
    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
