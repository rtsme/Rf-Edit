"""
Keep a whole RF Online server's .dat tables (and, verbatim, the client's data
files) in a git repo, edit them in an IDE, and build the changes back into an
install.

Library + CLI. The GUI in rf_workbench.py drives the same functions.
Global options (--repo, --server, --root) go BEFORE the subcommand.

    python rf_repo.py --repo D:\\rf-data --root server --server "C:\\...\\1_Server AOP" create
    python rf_repo.py --repo D:\\rf-data --root client --server "C:\\...\\2_Client AOP" create
    python rf_repo.py --repo D:\\rf-data status
    python rf_repo.py --repo D:\\rf-data build [--confirm] [--allow-create] [--seed-state]

`--repo` can point at a single root (has rfrepo.json directly) or at the
rf-data parent of named roots (server/, client/): status/build/sync-files
with no --root then operate on every root found, combined. `--root <name>`
targets exactly one.

Each root mirrors its install's folder structure, so a table that lives in
Zoneserver\\RF_Bin\\Map\\NeutralA on the server is at
server/csv/Zoneserver/RF_Bin/Map/NeutralA/<name>.csv in the repo, with its
schema beside it under server/schemas/.

The two roots convert different formats. The server root converts .dat through
rf_dat.py, one CSV per file. The client root converts .edf through rf_edf.py
(BACKLOG #100) -- an encrypted container holding many tables, so one file
becomes a *directory* of CSVs, csv/DataTable/Item.edf/00.csv onwards, with the
layouts and the file's own key under schemas/DataTable/Item.edf/. Everything
else on either side is copied verbatim into files/ -- see
docs/knowledge/client-file-formats.md.

Why the CSVs can be trusted as the source of truth: `create` re-imports every
CSV it writes, rebuilds the .dat (or the whole .edf, key and all), and
compares byte-for-byte against the original before accepting it. A file only
enters the repo if that trip is proven lossless for that exact file. What no
check can tell you is whether an *edit* was correct -- a valid number in the
wrong column is still valid -- so read `status` before you build.
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
from concurrent.futures import ThreadPoolExecutor

import rf_edf
from rf_dat import (SchemaError, Table, read_schema_json, record_size,
                    write_schema_json)

MANIFEST = "rfrepo.json"

# Local, gitignored cache of {abspath: [size, mtime_ns, sha256]} so status/
# build can skip re-reading a table's CSV or .dat when neither has changed
# since the sha was last computed (BACKLOG #27: diffing 3700+ tables by
# reading every one of them, every call, is the dominant cost). Content can't
# change without size or mtime changing too, so this is the same trust git
# places in its own stat cache -- not a correctness guarantee on its own, but
# the manifest sha comparison right after still decides SAME/CHANGED, so a
# wrongly-trusted stale entry only costs a re-read next run, never a wrong
# status.
STAT_CACHE_FILE = ".rf_repo_cache.json"

# I/O-bound and independent per table, so overlap the waits instead of
# hashing one file at a time -- see BACKLOG #27's profiling writeup.
HASH_WORKERS = 16

# Files copied into the repo byte-for-byte instead of being converted. They're
# already text; there is nothing to gain from parsing them and something to
# lose, since rewriting a config file is how you change behaviour by accident.
VERBATIM_EXTS = (".ini",)

# --- the client root (BACKLOG #9/#10/#100) ---------------------------------
#
# No client file uses the *server's* container format -- see
# docs/knowledge/client-file-formats.md -- so nothing here is a .dat table.
# The client's own converted format is .edf (BACKLOG #100): an encrypted
# OdinTeam container whose payload is a chain of tables, read by rf_edf.py.
# Everything else editable is still copied verbatim. The scan is restricted to
# the directories #9 actually scanned: DataTable/, System/, and the loose
# files at the client root. Map/, Character/, Chef/, item/, Effect/, Snd/,
# SpriteImage/, Redist/ are the immutable bulk layer (spec 02 S1) and belong
# to the asset store (#11) -- walking them here would be slow and wrong.
CLIENT_SCAN_DIRS = ("DataTable", "System")

# The client's converted format, handled by rf_edf.py rather than rf_dat.py.
# One .edf holds many tables, so it converts to a *directory* of CSVs named
# exactly like the file -- csv/DataTable/Item.edf/00.csv .. 46.csv -- with
# each table's frozen layout beside it under schemas/DataTable/Item.edf/, and
# EDF_META there too for the two facts no layout carries: which of the four
# readings was used, and the file's own 256-byte key.
#
# The key has to be kept because it is per file and lives *inside* the file:
# without it a clean clone could rebuild the payload and still not reproduce
# the .edf, which would make the CSVs a lossy copy rather than the source of
# truth (spec 02 S5). It is not a secret -- the codec is in rf_edf.py and the
# key ships in every client -- it is layout data, and it lives with the
# layouts.
EDF_EXT = ".edf"
EDF_META = "edf.json"

# Standard third-party formats -- verdict ASSET in the knowledge file. These
# belong to the asset store, not rf-data.
CLIENT_ASSET_EXTS = (".ttf", ".dds", ".jpg", ".jpeg", ".z", ".tga", ".lc",
                     ".dll", ".cso", ".pso", ".vso", ".sho", ".ani")

# rfoemf.dat is a TrueType font under a .dat name -- the one file the
# extension rule above gets wrong.
CLIENT_ASSET_PATH_OVERRIDES = ("System/rfoemf.dat",)

# Mutable binaries (spec 02 S1): exes, the patched RF_Online.bin, and
# adjacent native-code files at the client root. These live in rf-client
# directly with a PATCHES.md line per change (rule 8) -- rf-data's job is
# editable *data*, not code. Found running #10 for real; #9's scan (which
# only looked at "data directories") never enumerated them.
CLIENT_BINARY_EXTS = (".exe", ".bin", ".sys", ".asi")

# rf-client's own repo metadata sitting in the same working-copy folder --
# not client data at all.
CLIENT_META_EXCLUDE_PATHS = (".gitignore", "PATCHES.md")

# Runtime output that changes on every launch (#37) -- never tracked.
# init.r3o also leaks uninitialised process memory into git history.
# d3d9-proxy.log joins the six #9 found -- also missed by #9's scan.
CLIENT_EXCLUDE_PATHS = (
    "dlctemp.db",
    "sixrow-persist.log",
    "d3d9-proxy.log",
    "System/DefaultSet.tmp",
    "System/RFVisuals/rf-smaa.log",
    "System/RFVisuals/rf-visuals.log",
    "System/Shader/init.r3o",
)

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

# Local stat cache speeding up status/build (BACKLOG #27) -- machine-specific
# paths and mtimes, rebuilt automatically, never a source of truth.
%s
""" % STAT_CACHE_FILE

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

# The client root's csv/ and schemas/ are written ASCII-only with LF endings,
# exactly as the server root's are, and must stay that way for the same
# reason: these tables carry game text in a legacy encoding escaped as \\xNN,
# and a tool that "fixes" the encoding or the line endings corrupts fields
# nobody edited.
#
# files/ is different and keeps its own rule. The client's verbatim data is a
# mix of EUC-KR/cp949 text, CRLF text and binary blobs -- see
# docs/knowledge/client-file-formats.md -- so nothing there is known to be
# uniform, and every byte is kept exactly as read: no conversion at all. It
# comes last so it wins over the catch-all above it.
CLIENT_GITATTRIBUTES = """\
* text=auto eol=lf
*.csv text eol=lf
*.json text eol=lf
*.md text eol=lf

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

# For a verbatim-only root (client): no csv/, no schemas/, nothing to
# "build" in the table sense -- just files/ copied and diffed byte for byte.
README_TEMPLATE_VERBATIM = """\
# %(name)s

Verbatim, byte-for-byte copies of an RF Online install's data files, so they
can be diffed, reviewed and edited in a normal editor -- see
docs/knowledge/client-file-formats.md for why nothing here is converted.

Install this was created from:

    %(server)s

## Layout

- `files/` byte-for-byte copies. Editing one and building writes exactly
  those bytes back to the install.
- `%(manifest)s` records the install path and a sha256 + size per file.
- `build/`, `backups/` generated, git-ignored.

## Editing

Edit the file directly -- no schema, no columns, no round-trip proof beyond
"the bytes you wrote are the bytes that get built." Some files are legacy
EUC-KR/cp949 text (not UTF-8); `.gitattributes` disables all text/eol
conversion here so a checkout reproduces the exact bytes.

## Building back

    python rf_repo.py --repo <this folder> status
    python rf_repo.py --repo <this folder> build --confirm

`status` lists which files would change. `build` backs up every file it
overwrites into `backups/<timestamp>/` first.

## Coverage

%(coverage)s
"""


# For a root whose converted format is .edf (client): csv/ and schemas/ hold a
# directory per file rather than a file per table, and there is no .dat pass.
README_TEMPLATE_EDF = """\
# %(name)s

The `.edf` tables from an RF Online client, as CSV, so they can be diffed,
reviewed and edited in a normal editor instead of a hex editor -- plus every
other editable client file, copied byte for byte.

Install this was created from:

    %(server)s

## Layout

- `csv/` mirrors the client's folder structure. An `.edf` holds many tables,
  so each one becomes a *directory* named after the file --
  `csv/DataTable/Item.edf/00.csv`, `01.csv`, ... -- one CSV per table, one
  line per record, first line the field names. A table whose records nest
  writes a second CSV beside its own (`00.items.csv`, `00.<run>.csv`) joined
  by a `Block` column.
- `schemas/` the same directories again, holding each table's frozen layout
  (`00.json`) plus `%(edfmeta)s`: how the payload was read, and the file's own
  256-byte key. Both are needed to rebuild the `.edf` byte for byte with no
  client present.
- `files/` byte-for-byte copies of everything not converted.
- `%(manifest)s` records the install path and a checksum per entry.
- `build/`, `backups/` generated, git-ignored.

## Editing

**Columns are the binary record layout** -- don't add, remove or reorder them.
Rows can be added or removed freely; the rebuilt record count follows the
number of lines. Don't renumber the table CSVs either: a payload is its tables
laid end to end, so dropping `03.csv` would move every table after it.

- Bytes outside printable ASCII are escaped `\\xNN`, mostly the legacy Korean
  text. A literal backslash is `\\\\`. Leave these alone unless you mean to
  change them.
- `-1` is the usual "empty slot" marker.

Some files describe each other: `NDMap.edf` takes its group lengths from
`Map.edf`, so a change to one that alters those lengths has to be made in the
other too, or the pair stops reading.

## Building back

    python rf_repo.py --repo <this folder> status
    python rf_repo.py --repo <this folder> build --confirm

`status` lists which files would change and which of their tables. `build`
backs up every file it overwrites into `backups/<timestamp>/` first, and
refuses to write anything at all if any entry no longer rebuilds.

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


def find_client_verbatim(root):
    """Every client file that belongs in client/files/ -- see CLIENT_* above.

    Restricted to DataTable/, System/ and the loose files at the client root;
    everything else (the bulk asset directories) is out of scope for #10.
    """
    out = []
    for name in CLIENT_SCAN_DIRS:
        sub = os.path.join(root, name)
        if not os.path.isdir(sub):
            continue
        for dirpath, _dirs, files in os.walk(sub):
            for fn in files:
                out.append(os.path.relpath(os.path.join(dirpath, fn), root))
    for fn in os.listdir(root):
        if os.path.isfile(os.path.join(root, fn)):
            out.append(fn)

    def keep(rel):
        key = rel.replace("\\", "/")
        if (key in CLIENT_EXCLUDE_PATHS or key in CLIENT_ASSET_PATH_OVERRIDES
                or key in CLIENT_META_EXCLUDE_PATHS):
            return False
        ext = os.path.splitext(key)[1].lower()
        return ext not in CLIENT_ASSET_EXTS and ext not in CLIENT_BINARY_EXTS

    return sorted(rel for rel in out if keep(rel))


# Named root profiles for the CLI's --root flag. "server" is the historic
# default: full .dat conversion plus VERBATIM_EXTS (.ini) copying. "client"
# is verbatim-only -- see the CLIENT_* constants above.
#
# "server" also carries state_patterns (BACKLOG #85): files/ entries matching
# one of these are runtime state the running server rewrites on its own, not
# stable config. The whole SystemSave/ directory qualifies -- not just the 25
# *_Boss.ini boss-respawn files, but also ServerDisplay.ini (uptime/user
# counts/connection stats, rewritten continuously); RfServer's own .gitignore
# already excludes the entire directory on the same theory (BACKLOG #84).
# They stay tracked (a fresh install still needs them, spec 02 §5), but are
# never compared or overwritten by ordinary status/build -- see
# compute_state_keys() and build_to_server()'s seed_state.
#
# "client" converts .edf instead of .dat (BACKLOG #100): convert=False turns
# the .dat pass off, convert_edf=True turns the rf_edf.py pass on. The two are
# separate flags rather than one "format" name because they are separate
# passes over separate file sets, and a root could one day want both.
ROOT_PROFILES = {
    "server": {"convert": True, "convert_edf": False, "find_fn": None,
              "gitattributes": GITATTRIBUTES,
              "state_patterns": ["Zoneserver/SystemSave/*"]},
    "client": {"convert": False, "convert_edf": True,
              "find_fn": find_client_verbatim,
              "gitattributes": CLIENT_GITATTRIBUTES},
}


def compute_state_keys(files, profile):
    """Which files/ entries (a dict as returned by export_files) are runtime
    state the install rewrites on its own, per the owning profile's
    state_patterns. Returns a sorted list of keys, a subset of `files`.
    """
    patterns = ROOT_PROFILES.get(profile, {}).get("state_patterns", [])
    if not patterns:
        return []
    return sorted(k for k in files
                 if any(fnmatch.fnmatch(k, pat) for pat in patterns))


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


def read_stat_cache(repo):
    path = os.path.join(repo, STAT_CACHE_FILE)
    try:
        with open(path, "r", encoding="ascii") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def write_stat_cache(repo, cache):
    with open(os.path.join(repo, STAT_CACHE_FILE), "w", encoding="ascii",
              newline="\n") as f:
        json.dump(cache, f)


def cached_sha(path, cache):
    """sha(path), skipping the read if size+mtime match the cached entry.

    Raises the same OSError sha()/os.stat() would for a missing file --
    callers that used to guard with os.path.exists() can catch that instead,
    which also folds the existence check into the same stat() call.
    """
    st = os.stat(path)
    key = os.path.abspath(path)
    hit = cache.get(key)
    if hit and hit[0] == st.st_size and hit[1] == st.st_mtime_ns:
        return hit[2]
    digest = sha(path)
    cache[key] = [st.st_size, st.st_mtime_ns, digest]
    return digest


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


# -------------------------------------------------------------------- .edf

def edf_dirs(repo, rel):
    """`(csv dir, schemas dir)` for one .edf, both named exactly like the file.

    Keeping the `.edf` on the directory name is deliberate: the repo mirrors
    the install's folder structure, and `Item.edf/` can never collide with
    another entry the way a stripped `Item/` could.
    """
    native = rel.replace("/", os.sep)
    return (os.path.join(repo, "csv", native),
            os.path.join(repo, "schemas", native))


def write_edf_meta(schema_dir, rel, kind, key):
    """Freeze the two facts about an .edf that no table layout carries."""
    doc = {"edf": rel, "kind": kind, "key": key.hex()}
    with open(os.path.join(schema_dir, EDF_META), "w", encoding="ascii",
              newline="\n") as f:
        json.dump(doc, f, indent=1, sort_keys=True)
        f.write("\n")


def read_edf_meta(schema_dir):
    """`(kind, key)` from a schema directory's EDF_META, or raise."""
    path = os.path.join(schema_dir, EDF_META)
    try:
        with open(path, "r", encoding="ascii") as f:
            doc = json.load(f)
    except (OSError, ValueError) as e:
        raise SchemaError("%s: %s" % (path, e))
    for name in ("kind", "key"):
        if name not in doc:
            raise SchemaError("%s: no %s -- an .edf cannot be rebuilt without "
                              "both the reading and the key" % (path, name))
    try:
        key = bytes.fromhex(doc["key"])
    except ValueError:
        raise SchemaError("%s: key is not hex" % path)
    if len(key) != rf_edf.KEY_LENGTH:
        raise SchemaError("%s: key is %d bytes, must be %d"
                          % (path, len(key), rf_edf.KEY_LENGTH))
    return doc["kind"], key


def edf_repo_sha(repo, rel, cache=None):
    """One digest over everything the repo holds for one .edf.

    Every CSV under csv/<rel>/ and every layout under schemas/<rel>/, by name
    as well as by content, so adding, deleting or renaming a member changes it
    too. Hashing only the first CSV would miss a deleted `00.items.csv`, and
    then status would call a file unchanged that no longer rebuilds.
    """
    parts = []
    for label, base in zip(("csv", "schemas"), edf_dirs(repo, rel)):
        for dirpath, _dirs, names in os.walk(base):
            for fn in names:
                path = os.path.join(dirpath, fn)
                key = os.path.relpath(path, base).replace(os.sep, "/")
                digest = (cached_sha(path, cache) if cache is not None
                          else sha(path))
                parts.append("%s/%s %s" % (label, key, digest))
    if not parts:
        raise OSError("no csv/ or schemas/ copy of %s in the repo" % rel)
    return sha_bytes("\n".join(sorted(parts)).encode("ascii"))


def build_edf(repo, rel):
    """Rebuild one .edf from the repo. Returns (tables, bytes).

    The CSVs give the payload and EDF_META gives the reading and the key, so
    nothing here needs the install -- which is the whole point: a clean clone
    plus `build` has to reproduce the client's files exactly (spec 02 S5).
    """
    csv_dir, schema_dir = edf_dirs(repo, rel)
    kind, key = read_edf_meta(schema_dir)
    tables = rf_edf.import_tables(csv_dir, schema_dir)
    return tables, rf_edf.encrypt(rf_edf.build_payload(kind, tables), key)


def convert_edfs(server_root, repo, rels, progress=None):
    """Convert each .edf in `rels` into its csv/ and schemas/ directories.

    Returns (entries, skipped). The guarantee is the one `create` makes for a
    .dat table, and for the same reason: the CSVs are read back through their
    own frozen layouts, the payload rebuilt, the container re-encrypted with
    the file's own key, and the result compared byte for byte with the
    original before the entry is accepted. A file that fails is reported and
    left out, so it stays a verbatim blob under files/ rather than becoming a
    lossy CSV nobody can tell is lossy.
    """
    entries, skipped = {}, []
    for i, rel in enumerate(rels):
        if progress:
            progress(i, len(rels), rel)
        key_rel = rel.replace("\\", "/")
        src = os.path.join(server_root, rel)
        csv_dir, schema_dir = edf_dirs(repo, key_rel)
        try:
            _payload, key, kind, tables = rf_edf.read_tables(src)
            rf_edf.export_tables(tables, csv_dir, schema_dir,
                                 os.path.basename(rel))
            write_edf_meta(schema_dir, key_rel, kind, key)
            rebuilt = rf_edf.encrypt(
                rf_edf.build_payload(kind, rf_edf.import_tables(csv_dir,
                                                                schema_dir)),
                key)
        except (SchemaError, ValueError, OSError) as e:
            shutil.rmtree(csv_dir, ignore_errors=True)
            shutil.rmtree(schema_dir, ignore_errors=True)
            skipped.append((rel, str(e).split("\n")[0]))
            continue
        with open(src, "rb") as f:
            original = f.read()
        if rebuilt != original:
            shutil.rmtree(csv_dir, ignore_errors=True)
            shutil.rmtree(schema_dir, ignore_errors=True)
            skipped.append((rel, "CSV does not rebuild to the original bytes"))
            continue
        entries[key_rel] = {
            "edf_sha": sha_bytes(original),
            "repo_sha": edf_repo_sha(repo, key_rel),
            "kind": kind,
            "tables": len(tables),
            "records": sum(len(t.rows) for t in tables),
        }
    return entries, skipped


# ------------------------------------------------------------------ create

def create_repo(server_root, repo, progress=None, include=None, convert=True,
                find_fn=None, gitattributes=GITATTRIBUTES, profile=None,
                convert_edf=False):
    """Convert every convertible .dat under server_root into repo/csv/.

    profile selects a named entry from ROOT_PROFILES ("server" or "client"),
    setting convert/find_fn/gitattributes together and recording the choice
    in the manifest so a later sync-files knows which rules to reapply.
    Passed explicitly, convert/find_fn/gitattributes override profile's
    defaults (or work standalone with no profile at all).

    convert=False skips the .dat conversion pass entirely (the client root:
    no file there passes the *server's* container test, so there is nothing to
    attempt -- see docs/knowledge/client-file-formats.md). convert_edf=True
    runs the client's own conversion pass instead, through rf_edf.py.
    find_fn, if given, replaces find_verbatim() for the verbatim files/ pass
    (find_client_verbatim for the client root); it also decides which files
    the .edf pass sees, so the two passes always partition one scan and an
    .edf that fails to convert falls through to files/ rather than vanishing.

    Returns (manifest, converted, skipped) where skipped is a list of
    (rel_path, reason) -- tables that could not be represented losslessly and
    were therefore left out rather than half-imported.
    """
    if profile is not None:
        p = ROOT_PROFILES[profile]
        convert, find_fn, gitattributes = (p["convert"], p["find_fn"],
                                           p["gitattributes"])
        convert_edf = p.get("convert_edf", False)
    rels = find_dats(server_root) if convert else []
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

    edf = {}
    if convert_edf:
        scan = find_fn(server_root) if find_fn else find_verbatim(server_root)
        edf_rels = [r for r in scan if r.lower().endswith(EDF_EXT)]
        if progress:
            progress(0, len(edf_rels), "converting .edf")
        edf, edf_skipped = convert_edfs(server_root, repo, edf_rels,
                                        progress=progress)
        skipped += edf_skipped

    if progress:
        progress(total, total, "copying files")
    # Whatever converted is no longer a verbatim file: it lives in csv/ now,
    # and keeping a second byte-for-byte copy under files/ would make the
    # repo carry the same data twice and disagree with itself the moment one
    # side is edited (spec 02 S5). Whatever did NOT convert is still copied,
    # which is what makes a failed .edf safe.
    files, secrets = export_files(server_root, repo, progress=progress,
                                  find_fn=find_fn, skip=set(edf))

    manifest = {
        "server_root": os.path.abspath(server_root),
        "created": time.strftime("%Y-%m-%d %H:%M:%S"),
        "convert": convert,
        "convert_edf": convert_edf,
        "profile": profile,
        "tables": tables,
        "edf": edf,
        "skipped": {rel.replace("\\", "/"): why for rel, why in skipped},
        "files": files,
        "secrets": secrets,
        "state": compute_state_keys(files, profile),
    }
    os.makedirs(repo, exist_ok=True)
    write_manifest(repo, manifest)

    write_repo_meta(repo, server_root, manifest, n_dats=len(rels),
                    gitattributes=gitattributes)
    return manifest, tables, skipped


def write_repo_meta(repo, server_root, manifest, n_dats=None,
                    gitattributes=GITATTRIBUTES):
    """(Re)write README, .gitignore and .gitattributes from the manifest."""
    tables = manifest.get("tables", {})
    skipped = manifest.get("skipped", {})
    files = manifest.get("files", {})
    secrets = manifest.get("secrets", {})
    edf = manifest.get("edf", {})
    convert = manifest.get("convert", True)
    convert_edf = manifest.get("convert_edf", False)
    edf_skipped = [k for k in skipped if k.lower().endswith(EDF_EXT)]
    if n_dats is None:
        n_dats = len(tables) + len(skipped) - len(edf_skipped)
    if convert:
        coverage = (
            "%d of %d .dat files under the server root are in this repo. The "
            "other %d could not be represented losslessly and were left out; "
            "see `skipped` in %s for the reason per file.\n\n"
            "%d config file(s) are copied verbatim, byte for byte, under "
            "`files/`. They are not converted -- they are already text -- so "
            "editing one in the repo and building copies exactly those bytes "
            "back to the server."
            % (len(tables), n_dats, len(skipped) - len(edf_skipped), MANIFEST,
               len(files)))
    elif convert_edf:
        coverage = (
            "%d of %d .edf files under the install root are converted into "
            "`csv/` -- %d table(s) in all, %d record(s). Each file becomes a "
            "directory of CSVs with its frozen layouts under `schemas/`, and "
            "a scratch `build` reproduces every one of them sha256-identical "
            "to the client it came from.\n\n"
            "%d could not be represented losslessly and stay verbatim blobs "
            "under `files/` instead; see `skipped` in %s for the reason per "
            "file. Verbatim is a supported end state, not a failure.\n\n"
            "%d further file(s) are copied verbatim, byte for byte, under "
            "`files/` -- no codec, or already text. Editing one in the repo "
            "and building copies exactly those bytes back to the install."
            % (len(edf), len(edf) + len(edf_skipped),
               sum(e.get("tables", 0) for e in edf.values()),
               sum(e.get("records", 0) for e in edf.values()),
               len(edf_skipped), MANIFEST, len(files)))
    else:
        coverage = (
            "This is a verbatim-only root: no file here passes rf_dat.py's "
            "container test, so `csv/` stays empty -- see "
            "docs/knowledge/client-file-formats.md for the per-file verdicts. "
            "%d file(s) are copied byte for byte under `files/`. Editing one "
            "in the repo and building copies exactly those bytes back to the "
            "install." % len(files))
    state = manifest.get("state", [])
    gitignore = GITIGNORE
    if state:
        coverage += (
            "\n\n%d of those config files are runtime state the running "
            "server rewrites on its own (BACKLOG #85), not stable config -- "
            "`status`/`build` never compare or overwrite one; `build "
            "--confirm --seed-state` places only whichever are entirely "
            "absent from the install." % len(state))
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
    if convert:
        readme_template = README_TEMPLATE
    elif convert_edf:
        readme_template = README_TEMPLATE_EDF
    else:
        readme_template = README_TEMPLATE_VERBATIM
    for name, text in ((".gitignore", gitignore),
                       (".gitattributes", gitattributes),
                       ("README.md", readme_template % {
                           "name": os.path.basename(os.path.abspath(repo)),
                           "server": os.path.abspath(server_root),
                           "manifest": MANIFEST,
                           "edfmeta": EDF_META,
                           "coverage": coverage})):
        with open(os.path.join(repo, name), "w", encoding="ascii",
                  newline="\n") as f:
            f.write(text)


def sync_files(repo, server_root=None, exts=VERBATIM_EXTS, progress=None):
    """Refresh only the verbatim files/ tree of an existing repo.

    Lets config files be added to a repo whose tables are already exported,
    without spending twenty minutes reconverting several thousand .dat files
    that haven't changed. Reapplies the same profile (server/client) the repo
    was created with, if any -- so a client repo's sync-files doesn't need to
    be told find_client_verbatim again.

    Entries the repo already converts are skipped, so this never drags an
    .edf back into files/ as a second, verbatim copy of a file csv/ already
    holds. Refreshing those means `create`, not `sync-files`.
    """
    manifest = read_manifest(repo)
    server_root = server_root or manifest["server_root"]
    profile = manifest.get("profile")
    find_fn = ROOT_PROFILES[profile]["find_fn"] if profile else None
    gitattributes = (ROOT_PROFILES[profile]["gitattributes"] if profile
                     else GITATTRIBUTES)
    files, secrets = export_files(server_root, repo, exts, progress=progress,
                                  find_fn=find_fn,
                                  skip=set(manifest.get("edf", {})))
    manifest["files"] = files
    manifest["secrets"] = secrets
    manifest["state"] = compute_state_keys(files, profile)
    write_manifest(repo, manifest)
    write_repo_meta(repo, server_root, manifest, gitattributes=gitattributes)
    return files, secrets


def export_files(server_root, repo, exts=VERBATIM_EXTS, progress=None,
                 find_fn=None, skip=()):
    """Copy the server's config files into repo/files/ byte-for-byte.

    Returns (files, secrets). `secrets` maps a repo-relative path to the
    credential keys found in it; those paths are also written into .gitignore
    so they stay in the working tree -- editable, and buildable back to the
    server -- without ever entering git history.

    `skip` names entries this root converts instead (the client's .edf files,
    BACKLOG #100), by the same forward-slash key the manifest uses. They are
    not verbatim files and must not be copied a second time.
    """
    rels = find_fn(server_root) if find_fn else find_verbatim(server_root, exts)
    if skip:
        rels = [r for r in rels if r.replace("\\", "/") not in skip]
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
    # A manifest entry with no copy in repo/files/: distinct from ERROR
    # because it must not block building everything else (#79/#84's
    # ServerState.ini) -- there is simply nothing to write for this one.
    NOREPO = "no_repo"

    # A converted .dat, a verbatim copy, or a converted .edf -- three
    # different things to rebuild and three different diffs to show.
    TABLE, FILE, EDF = "table", "file", "edf"

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

    def table_paths(rel):
        native = rel.replace("/", os.sep)
        return (os.path.join(repo, "csv", rel_to_csv(native)),
                os.path.join(server_root, native))

    def hash_one(rel):
        csv_path, dat_path = table_paths(rel)
        try:
            csv_sha = cached_sha(csv_path, cache)
        except OSError:
            return None, None
        try:
            dat_sha = cached_sha(dat_path, cache)
        except OSError:
            return csv_sha, None
        return csv_sha, dat_sha

    cache = read_stat_cache(repo)
    with ThreadPoolExecutor(max_workers=HASH_WORKERS) as ex:
        hashes = list(ex.map(hash_one, rels))
    write_stat_cache(repo, cache)

    out = []
    for i, rel in enumerate(rels):
        if progress:
            progress(i, total, rel)
        entry = manifest["tables"][rel]
        native = rel.replace("/", os.sep)
        csv_path, dat_path = table_paths(rel)
        csv_sha, dat_sha = hashes[i]

        if csv_sha is None:
            out.append(Status(rel, Status.ERROR, "csv is missing from the repo"))
            continue
        if dat_sha is None:
            out.append(Status(rel, Status.GONE, "not on the server"))
            continue

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

    out.extend(diff_edf(repo, server_root, manifest, cache, progress=progress))
    # Again: the .edf pass hashes a few hundred more files into the same cache.
    write_stat_cache(repo, cache)
    out.extend(diff_files(repo, server_root, manifest))
    return out


# Regions a table may carry beside its rows: a block or pool table's items, a
# nested table's runs, a group table's lengths. They are part of the record
# data and a diff that ignored them would call a real edit "same".
EDF_REGIONS = ("items", "runs", "groups")


def edf_delta(live_tables, repo_tables):
    """Where two readings of one .edf differ. [(table index or None, detail)]."""
    if len(live_tables) != len(repo_tables):
        return [(None, "table count %d -> %d"
                 % (len(live_tables), len(repo_tables)))]
    out = []
    for i, (live, mine) in enumerate(zip(live_tables, repo_tables)):
        if len(live.rows) != len(mine.rows):
            out.append((i, "record count %d -> %d"
                        % (len(live.rows), len(mine.rows))))
            continue
        n = sum(1 for a, b in zip(live.rows, mine.rows) if a != b)
        moved = [name for name in EDF_REGIONS
                 if getattr(live, name, None) != getattr(mine, name, None)]
        if not n and not moved:
            continue
        detail = "%d record(s) changed" % n if n else ""
        if moved:
            detail += ("%s%s differ" % (", " if detail else "",
                                        " and ".join(moved)))
        out.append((i, detail))
    return out


def edf_changes(repo, rel, server_root, tables=None, blob=None, limit=8):
    """Per-table detail for one changed .edf, for status and the GUI.

    Reads the install's own copy back through the same layers `create` used,
    so the answer is in records rather than in byte offsets. If the install's
    copy no longer reads at all -- someone edited it by hand, or an earlier
    build wrote a corrupt one -- that is said plainly instead of guessed at.

    `tables`/`blob` let a caller that has already rebuilt the file hand the
    result over; Item.edf is 15 MB and rebuilding it twice to print one line
    is not free.
    """
    live_path = os.path.join(server_root, rel.replace("/", os.sep))
    if tables is None or blob is None:
        tables, blob = build_edf(repo, rel)
    with open(live_path, "rb") as f:
        live = f.read()
    try:
        _p, _k, _kind, live_tables = rf_edf.read_tables(live_path)
    except (SchemaError, ValueError, OSError) as e:
        return None, ("%d -> %d bytes; the install's own copy does not read "
                      "back (%s)" % (len(live), len(blob),
                                     str(e).split("\n")[0]))
    deltas = edf_delta(live_tables, tables)
    if not deltas:
        return deltas, ("%d -> %d bytes, but every table reads the same -- "
                        "the container framing differs"
                        % (len(live), len(blob)))
    shown = "; ".join("table %s: %s" % ("?" if i is None else i, why)
                      for i, why in deltas[:limit])
    if len(deltas) > limit:
        shown += "; +%d more" % (len(deltas) - limit)
    return deltas, shown


def diff_edf(repo, server_root, manifest, cache, progress=None):
    """Compare every .edf the repo converts against the install. [Status].

    Same fast path the tables get: when the repo side and the install side
    both still hash to what the manifest recorded, nothing is parsed. When
    either moved, the CSVs are rebuilt into a whole .edf and diffed against
    the install byte for byte -- the CSVs are the source of truth, and the
    only thing that can prove them is rebuilding what they claim to describe.

    An entry that will not rebuild is ERROR, which blocks `build` for the
    whole root: a grammar that stopped fitting or a stamped directory that
    contradicts itself must never reach the install as a half-written file.
    """
    out = []
    rels = sorted(manifest.get("edf", {}))
    for i, rel in enumerate(rels):
        if progress:
            progress(i, len(rels), rel)
        entry = manifest["edf"][rel]
        live_path = os.path.join(server_root, rel.replace("/", os.sep))
        try:
            repo_sha = edf_repo_sha(repo, rel, cache)
        except OSError as e:
            out.append(Status(rel, Status.ERROR, str(e), kind=Status.EDF))
            continue
        try:
            live_sha = cached_sha(live_path, cache)
        except OSError:
            out.append(Status(rel, Status.GONE, "not on the install",
                              kind=Status.EDF))
            continue
        if (repo_sha == entry.get("repo_sha")
                and live_sha == entry.get("edf_sha")):
            out.append(Status(rel, Status.SAME, kind=Status.EDF))
            continue
        try:
            _tables, blob = build_edf(repo, rel)
        except (SchemaError, ValueError, OSError) as e:
            out.append(Status(rel, Status.ERROR, str(e).split("\n")[0],
                              kind=Status.EDF))
            continue
        if sha_bytes(blob) == live_sha:
            out.append(Status(rel, Status.SAME, kind=Status.EDF))
            continue
        try:
            _deltas, detail = edf_changes(repo, rel, server_root,
                                          tables=_tables, blob=blob)
        except (SchemaError, ValueError, OSError) as e:
            detail = str(e).split("\n")[0]
        out.append(Status(rel, Status.CHANGED, detail, kind=Status.EDF))
    return out


def diff_files(repo, server_root, manifest):
    """Compare the verbatim copies in repo/files/ against the server.

    A key also listed in manifest["secrets"] is a real credential file
    deliberately left out of repo/files/ (rule 12: secrets never enter git,
    only .example templates are tracked) - it is not a broken table, so it
    is skipped here rather than reported as ERROR and blocking every build.

    A key listed in manifest["state"] (BACKLOG #85) is runtime state the
    running server rewrites on its own -- comparing it to the repo's snapshot
    would report drift that is expected and never "wrong", so it is skipped
    here the same way. build_to_server's seed_state is the only path that
    ever writes one, and only when the install lacks it entirely.
    """
    out = []
    secrets = manifest.get("secrets", {})
    state = set(manifest.get("state", []))
    for key in sorted(manifest.get("files", {})):
        if key in secrets or key in state:
            continue
        native = key.replace("/", os.sep)
        repo_path = os.path.join(repo, "files", native)
        live_path = os.path.join(server_root, native)
        if not os.path.exists(repo_path):
            out.append(Status(key, Status.NOREPO,
                              "manifest lists it but there's no copy in "
                              "files/ -- run sync-files to capture it, or "
                              "drop the entry",
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
                    allow_create=False, seed_state=False, progress=None):
    """Write changed (and, with allow_create, missing) entries to the server.

    Returns (written, backup_dir). With apply=False nothing is written; the
    return value is the list that *would* be written, which is what the GUI
    previews.

    GONE entries -- present in the repo, absent from the install -- are
    never included unless allow_create is set: build must never silently
    repopulate a live install that is deliberately thin (#79).

    manifest["state"] entries (BACKLOG #85: e.g. the 26 SystemSave/*_Boss.ini
    boss-respawn files) never appear in `statuses` at all -- diff_files skips
    them, so allow_create can't reach them either. seed_state is the one way
    to write one, and only for whichever are entirely absent from the
    install: never overwrites one that already exists, however different its
    content, because that content is live server state, not stale data.
    """
    manifest = read_manifest(repo)
    server_root = server_root or manifest["server_root"]
    statuses = diff_repo(repo, server_root, progress=progress)
    pending = [s for s in statuses if s.state == Status.CHANGED]
    if allow_create:
        pending += [s for s in statuses if s.state == Status.GONE]
    if seed_state:
        for key in manifest.get("state", []):
            native = key.replace("/", os.sep)
            if os.path.exists(os.path.join(server_root, native)):
                continue  # already there -- never overwrite live state
            if not os.path.exists(os.path.join(repo, "files", native)):
                continue  # nothing captured to seed from
            pending.append(Status(key, Status.GONE,
                                  "seed: absent from install (runtime "
                                  "state, written once)", kind=Status.FILE))
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
        os.makedirs(os.path.dirname(live_path), exist_ok=True)
        if os.path.exists(live_path):
            bak = os.path.join(backup_dir, native)
            os.makedirs(os.path.dirname(bak), exist_ok=True)
            shutil.copy2(live_path, bak)
        # else: new file, nothing to back up.

        if s.kind == Status.FILE:
            # Verbatim: copy the bytes back exactly as they sit in the repo.
            with open(os.path.join(repo, "files", native), "rb") as f:
                blob = f.read()
            with open(live_path, "wb") as f:
                f.write(blob)
            manifest["files"][s.rel]["sha"] = sha_bytes(blob)
            manifest["files"][s.rel]["bytes"] = len(blob)
        elif s.kind == Status.EDF:
            # Rebuilt from the CSVs and re-encrypted with the file's own key.
            # Anything that would not rebuild was already an ERROR above, so
            # nothing half-written can reach the install from here.
            _tables, blob = build_edf(repo, s.rel)
            with open(live_path, "wb") as f:
                f.write(blob)
            manifest["edf"][s.rel]["edf_sha"] = sha_bytes(blob)
            manifest["edf"][s.rel]["repo_sha"] = edf_repo_sha(repo, s.rel)
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


def discover_roots(repo):
    """Named subdirectories of repo that are themselves rf-data roots."""
    out = []
    if not os.path.isdir(repo):
        return out
    for name in sorted(os.listdir(repo)):
        sub = os.path.join(repo, name)
        if os.path.isdir(sub) and os.path.exists(os.path.join(sub, MANIFEST)):
            out.append(name)
    return out


def resolve_roots(repo, root_arg):
    """[(name, path)] to operate on for status/build/sync-files.

    --root <name> targets exactly that subdirectory. Omitted (or "all"): if
    `repo` is itself a repo (has rfrepo.json, the pre-multi-root single-root
    shape), that one root; otherwise every named subdirectory that is one --
    the "combined" mode spec 02 S3 asks for.
    """
    if root_arg and root_arg != "all":
        return [(root_arg, os.path.join(repo, root_arg))]
    if os.path.exists(os.path.join(repo, MANIFEST)):
        return [(None, repo)]
    names = discover_roots(repo)
    if not names:
        raise SystemExit(
            "%s has no %s and no named root subdirectory (server/, client/) "
            "-- nothing to operate on." % (repo, MANIFEST))
    return [(name, os.path.join(repo, name)) for name in names]


def cmd_create(args):
    if not args.server:
        raise SystemExit("--server is required for create")
    target = os.path.join(args.repo, args.root) if args.root else args.repo
    profile = args.root if args.root in ROOT_PROFILES else None
    manifest, tables, skipped = create_repo(args.server, target,
                                            progress=_bar, profile=profile)
    edf = manifest.get("edf", {})
    print("\n\ncreated %s" % os.path.abspath(target))
    print("  %d table(s) converted" % len(tables))
    if edf:
        print("  %d .edf converted -- %d table(s), %d record(s)"
              % (len(edf), sum(e["tables"] for e in edf.values()),
                 sum(e["records"] for e in edf.values())))
    print("  %d skipped" % len(skipped))
    reasons = {}
    for rel, why in skipped:
        reasons.setdefault(why, []).append(rel)
    for why, rels in sorted(reasons.items(), key=lambda kv: -len(kv[1])):
        print("    %5d  %s" % (len(rels), why[:90]))
    print("  %d file(s) copied verbatim" % len(manifest.get("files", {})))
    return 0


def _check_single_server_override(roots, server_arg):
    if server_arg and len(roots) > 1:
        raise SystemExit(
            "--server only applies to a single root; pass --root to target "
            "one, or drop --server to use each root's own recorded path.")


def cmd_sync_files(args):
    roots = resolve_roots(args.repo, args.root)
    _check_single_server_override(roots, args.server)
    for name, path in roots:
        if name:
            print("=== %s ===" % name)
        files, secrets = sync_files(path, args.server, progress=_bar)
        sys.stdout.write("\r" + " " * 78 + "\r")
        print("%d file(s) copied into files/" % len(files))
        if secrets:
            print("\n%d contain credentials and were added to .gitignore:"
                  % len(secrets))
            for key in sorted(secrets):
                print("  %-56s (%s)" % (key, ", ".join(secrets[key])))
            print("\nThey are still on disk and still build back to the "
                  "install; they just won't be committed.")
    return 0


def cmd_status(args):
    roots = resolve_roots(args.repo, args.root)
    _check_single_server_override(roots, args.server)
    any_broken = False
    for name, path in roots:
        if name:
            print("=== %s ===" % name)
        manifest = read_manifest(path)
        n_state = len(manifest.get("state", []))
        statuses = diff_repo(path, args.server, progress=_bar)
        sys.stdout.write("\r" + " " * 78 + "\r")
        changed = [s for s in statuses if s.state == Status.CHANGED]
        broken = [s for s in statuses if s.state == Status.ERROR]
        gone = [s for s in statuses if s.state == Status.GONE]
        norepo = [s for s in statuses if s.state == Status.NOREPO]
        if changed:
            print("WOULD CHANGE (%d):" % len(changed))
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
            print("in the repo but not on the install: %d (build --confirm "
                  "--allow-create places these)\n" % len(gone))
        if norepo:
            print("WARNING -- tracked in the manifest but missing from the "
                  "repo's files/ (%d), skipped rather than blocking build:"
                  % len(norepo))
            for s in norepo:
                print("  %-58s %s" % (s.rel[-58:], s.detail[:60]))
            print()
        if n_state:
            print("runtime state, not compared (%d): the running server "
                  "rewrites these on its own (e.g. boss respawn state); "
                  "ordinary status/build never touches them -- 'build "
                  "--confirm --seed-state' places only whichever are "
                  "entirely absent from the install\n" % n_state)
        print("%d unchanged, %d changed, %d missing, %d broken, %d no-repo"
              % (len(statuses) - len(changed) - len(broken) - len(gone)
                 - len(norepo),
                 len(changed), len(gone), len(broken), len(norepo)))
        any_broken = any_broken or bool(broken)
    return 1 if any_broken else 0


def cmd_build(args):
    roots = resolve_roots(args.repo, args.root)
    _check_single_server_override(roots, args.server)
    for name, path in roots:
        if name:
            print("=== %s ===" % name)
        pending, backup = build_to_server(path, args.server,
                                          apply=args.confirm,
                                          allow_create=args.allow_create,
                                          seed_state=args.seed_state,
                                          progress=_bar)
        sys.stdout.write("\r" + " " * 78 + "\r")
        if not pending:
            print("Nothing to build -- the install already matches the repo.")
            continue
        for s in pending:
            tag = "[create]" if s.state == Status.GONE else "[update]"
            print("  %s %-49s %s" % (tag, s.rel[-49:], s.detail))
        created = sum(1 for s in pending if s.state == Status.GONE)
        updated = len(pending) - created
        if args.confirm:
            print("\nWrote %d file(s): %d updated, %d created."
                  % (len(pending), updated, created))
            if updated:
                print("Originals of updated files backed up to\n  %s"
                      % backup)
        else:
            print("\n%d file(s) would change (%d update, %d create). Nothing "
                  "written -- re-run with --confirm to apply." %
                  (len(pending), updated, created))
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--repo", required=True,
                   help="repo directory -- a single root, or the rf-data "
                   "parent of named roots (server/, client/)")
    p.add_argument("--server", default=None,
                   help="install root (defaults to the one recorded in the "
                   "repo; only valid when exactly one root is in play)")
    p.add_argument("--root", default=None,
                   help="which named root under --repo to operate on "
                   "(server, client, ...). status/build/sync-files: omitted "
                   "or 'all' means every root found under --repo, combined. "
                   "create: required unless --repo is already a single root.")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("create", help="install -> new repo").set_defaults(
        func=cmd_create)
    sub.add_parser("sync-files",
                   help="refresh only the verbatim files -- reads install "
                   "-> repo and rewrites the manifest from what it finds, "
                   "so on an install missing files the repo tracks it will "
                   "DROP those entries from rf-data. The opposite direction "
                   "from build; never use it to place a missing file."
                   ).set_defaults(func=cmd_sync_files)
    sub.add_parser("status", help="what would change on the install").set_defaults(
        func=cmd_status)
    b = sub.add_parser("build", help="write changed tables to the install")
    b.add_argument("--confirm", action="store_true",
                   help="actually write (without it, only lists changes)")
    b.add_argument("--allow-create", action="store_true",
                   help="also create entries the repo tracks but the "
                   "install lacks. Opt-in and never implied by --confirm "
                   "alone, so build can't silently repopulate a live "
                   "install that's deliberately thin.")
    b.add_argument("--seed-state", action="store_true",
                   help="also place manifest[\"state\"] entries (e.g. the "
                   "SystemSave/*_Boss.ini boss-respawn files) that are "
                   "entirely absent from the install -- never overwrites "
                   "one that already exists, since that content is live "
                   "server state, not stale data. Needed once on a "
                   "genuinely fresh install; never implied by "
                   "--allow-create.")
    b.set_defaults(func=cmd_build)
    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
