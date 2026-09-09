"""
Round-trip every .dat in the server script folder through rf_dat.

For each file: find a schema, parse it, re-encode it, and compare against the
original bytes. A file is only safe to edit through this tool once it shows OK
here -- that check is what proves the schema is right rather than merely
plausible.

    python verify_all.py <script_dir>

`script_dir` is required: this repo has no fixed idea of where a live
server's `Zoneserver\\RF_Bin\\script` folder is on any given machine (BACKLOG
#143), so guessing one here would silently drift the way the old hardcoded
default did.
"""
import os
import sys

from rf_dat import Table, SchemaError


def main(argv):
    if len(argv) < 2:
        print("usage: python verify_all.py <script_dir>", file=sys.stderr)
        print("no default: point it at a live server's "
              "Zoneserver\\RF_Bin\\script folder (BACKLOG #143)", file=sys.stderr)
        return 1
    script_dir = argv[1]
    names = sorted(f for f in os.listdir(script_dir) if f.lower().endswith(".dat"))
    ok, bad, noschema = [], [], []
    width = max(len(n) for n in names)
    for fn in names:
        path = os.path.join(script_dir, fn)
        try:
            t = Table.open(path)
        except SchemaError as e:
            noschema.append((fn, str(e).replace("\n", " ")))
            print("%-*s  NO SCHEMA" % (width, fn))
            continue
        good = t.roundtrip_ok()
        (ok if good else bad).append(fn)
        print("%-*s  %-8s %6d rec  %s"
              % (width, fn, "OK" if good else "MISMATCH", len(t.rows),
                 t.schema_source))

    print("\n%d OK, %d round-trip mismatch, %d no schema"
          % (len(ok), len(bad), len(noschema)))
    if bad:
        print("\nmismatched (schema fits the header but bytes differ):")
        for fn in bad:
            print("  " + fn)
    if noschema:
        print("\nno usable schema:")
        for fn, why in noschema:
            print("  %s\n      %s" % (fn, why[:160]))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
