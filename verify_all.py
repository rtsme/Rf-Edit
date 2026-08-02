"""
Round-trip every .dat in the server script folder through rf_dat.

For each file: find a schema, parse it, re-encode it, and compare against the
original bytes. A file is only safe to edit through this tool once it shows OK
here -- that check is what proves the schema is right rather than merely
plausible.

    python verify_all.py [script_dir]
"""
import os
import sys

from rf_dat import Table, SchemaError

DEFAULT_DIR = os.environ.get(
    "RF_SCRIPT_DIR",
    r"C:\client and server\1_Server AOP\Zoneserver\RF_Bin\script")


def main(argv):
    script_dir = argv[1] if len(argv) > 1 else DEFAULT_DIR
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
