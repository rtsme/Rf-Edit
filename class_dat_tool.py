"""
Reader/writer for RF Online's Class.dat (server-side class table),
built and verified against a server on the AoP 4.15 build.

Schema derived from the GU 2019 parser's Class.txt export (98 named
fields), plus one extra leading "Index" dword confirmed present in this
server's Class.dat by direct inspection of its header and record
boundaries -- the file header stores field_count=99, and the first
4 bytes of every record are a sequential 0,1,2,3... index that isn't in
the older parser's schema. This was confirmed by a byte-for-byte
round-trip test (read -> export -> re-import -> write -> diff against
the original) -- see the __main__ block below.

If you point this at a Class.dat from a different server build and the
round-trip test fails, the SCHEMA below needs updating for that build
before you trust it with real edits.

Usage:
    python class_dat_tool.py Class.dat
        Parses Class.dat, exports class_export.tsv (tab-separated, opens
        directly in Excel), re-imports it, writes class_roundtrip.dat,
        and reports whether the round trip was byte-identical.

    from class_dat_tool import read_class_dat, write_class_dat, export_tsv, import_tsv
        Use these directly once you're ready to make real edits:
            rows, trailing = read_class_dat("Class.dat")
            export_tsv(rows, "class_export.tsv")
            # ... edit class_export.tsv in Excel ...
            rows = import_tsv("class_export.tsv")
            write_class_dat("Class.dat", rows, trailing)
"""
import struct
import csv

HEADER_FMT = "<3I"  # record_count, field_count, record_size
HEADER_SIZE = struct.calcsize(HEADER_FMT)

# (field_name, type) in on-disk order. type is "dword" (4 bytes, uint32)
# or "string64" (64 bytes, null-padded).
SCHEMA = [
    ("Index", "dword"),
    ("Code", "string64"),
    ("Race", "dword"), ("Class", "dword"), ("Icon", "dword"),
    ("Grade", "dword"), ("UpGradeLv", "dword"),
    ("Ch_Class1", "string64"), ("Ch_Class2", "string64"),
    ("Ch_Class3", "string64"), ("Ch_Class4", "string64"),
    ("Ch_Class5", "string64"), ("Ch_Class6", "string64"),
    ("Ch_Class7", "string64"), ("Ch_Class8", "string64"),
    ("Temp", "string64"), ("KorName", "string64"), ("EngName", "string64"),
    ("ConLim", "dword"),
    ("LinkSkill1", "string64"), ("LinkSkill2", "string64"),
    ("LinkSkill3", "string64"), ("LinkSkill4", "string64"),
    ("LinkSkill5", "string64"), ("LinkSkill6", "string64"),
    ("LinkSkill7", "string64"), ("LinkSkill8", "string64"),
    ("LinkSkill9", "string64"), ("LinkSkill10", "string64"),
    ("IsUnitUsable", "dword"), ("IsAnimusUsable", "dword"),
    ("IsLauncherUsable", "dword"), ("IsWMKTUsable", "dword"),
    ("IsDMKTUsable", "dword"), ("IsBMKTUsable", "dword"),
    ("TrapMaxNum", "dword"),
    ("BnsHP", "dword"), ("BnsFP", "dword"), ("BnsSP", "dword"),
    ("UpValueDefMastery", "dword"),
    ("MeleMastery", "dword"), ("RangeMastery2", "dword"),
    ("SpecialMastery", "dword"), ("DefMastery", "dword"),
    ("ShieldMastery", "dword"),
    ("MakeMastery1", "dword"), ("MakeMastery2", "dword"), ("MakeMastery3", "dword"),
    ("MeleYchenik", "dword"), ("MeleExpert", "dword"),
    ("MeleElite", "dword"), ("MeleMagistr", "dword"),
    ("RangeYchenik", "dword"), ("RangeExpert", "dword"),
    ("RangeElite", "dword"), ("RangeMagistr", "dword"),
    ("DarkYch", "dword"), ("DarkExp", "dword"), ("DarkEl", "dword"), ("DarkMag", "dword"),
    ("HolyYch", "dword"), ("HolyExp", "dword"), ("HolyEl", "dword"), ("HolyMag", "dword"),
    ("Fire1", "dword"), ("Fire2", "dword"), ("Fire3", "dword"), ("Fire4", "dword"),
    ("Aqua1", "dword"), ("Aqua2", "dword"), ("Aqua3", "dword"), ("Aqua4", "dword"),
    ("Soil1", "dword"), ("Soil2", "dword"), ("Soil3", "dword"), ("Soil4", "dword"),
    ("Wind1", "dword"), ("Wind2", "dword"), ("Wind3", "dword"), ("Wind4", "dword"),
    ("IsSelectReward", "dword"),
    ("Reward1", "string64"), ("Amount1", "dword"),
    ("Reward2", "string64"), ("Amount2", "dword"),
    ("Reward3", "string64"), ("Amount3", "dword"),
    ("Reward4", "string64"), ("Amount4", "dword"),
    ("Reward5", "string64"), ("Amount5", "dword"),
    ("Reward6", "string64"), ("Amount6", "dword"),
    ("Reward7", "string64"), ("Amount7", "dword"),
    ("Reward8", "string64"), ("Amount8", "dword"),
    ("Reward9", "string64"), ("Amount9", "dword"),
]

FIELD_WIDTH = {"dword": 4, "string64": 64}
RECORD_SIZE = sum(FIELD_WIDTH[t] for _, t in SCHEMA)


def _decode(raw, ftype):
    if ftype == "dword":
        return struct.unpack("<I", raw)[0]
    # latin-1 is a lossless 1:1 byte<->char mapping, so this round-trips
    # ANY byte sequence exactly -- including the Korean (non-UTF8) bytes
    # in KorName -- even though it won't display as readable Korean text
    # in the TSV. Don't "fix" this to utf-8/cp949 unless you also update
    # _encode to match, or you'll corrupt KorName on write-back.
    return raw.split(b"\x00", 1)[0].decode("latin-1")


def _encode(value, ftype):
    if ftype == "dword":
        return struct.pack("<I", int(value))
    b = str(value).encode("latin-1")[:64]
    return b + b"\x00" * (64 - len(b))


def read_class_dat(path):
    """Returns (rows, trailing_bytes). rows is a list of dicts, one per class."""
    with open(path, "rb") as f:
        data = f.read()
    count, field_count, record_size = struct.unpack_from(HEADER_FMT, data, 0)
    if record_size != RECORD_SIZE:
        raise ValueError(
            f"record size mismatch: file header says {record_size} bytes/record, "
            f"SCHEMA computes {RECORD_SIZE} -- SCHEMA is out of date for this "
            f"file. Do not write with this SCHEMA until that's resolved."
        )
    if field_count != len(SCHEMA):
        raise ValueError(
            f"field count mismatch: file header says {field_count} fields, "
            f"SCHEMA has {len(SCHEMA)} -- SCHEMA is out of date."
        )
    rows = []
    offset = HEADER_SIZE
    for _ in range(count):
        block = data[offset:offset + record_size]
        row = {}
        pos = 0
        for name, ftype in SCHEMA:
            w = FIELD_WIDTH[ftype]
            row[name] = _decode(block[pos:pos + w], ftype)
            pos += w
        rows.append(row)
        offset += record_size
    trailing = data[offset:]  # anything after the last record (expect empty)
    return rows, trailing


def write_class_dat(path, rows, trailing=b""):
    header = struct.pack(HEADER_FMT, len(rows), len(SCHEMA), RECORD_SIZE)
    body = bytearray()
    for row in rows:
        for name, ftype in SCHEMA:
            body += _encode(row[name], ftype)
    with open(path, "wb") as f:
        f.write(header)
        f.write(bytes(body))
        f.write(trailing)


def export_tsv(rows, tsv_path):
    fieldnames = [name for name, _ in SCHEMA]
    with open(tsv_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames, delimiter="\t")
        w.writeheader()
        w.writerows(rows)


def import_tsv(tsv_path):
    with open(tsv_path, "r", newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f, delimiter="\t")
        rows = []
        for r in reader:
            row = {}
            for name, ftype in SCHEMA:
                row[name] = int(r[name]) if ftype == "dword" else r[name]
            rows.append(row)
    return rows


if __name__ == "__main__":
    import sys, filecmp
    src = sys.argv[1] if len(sys.argv) > 1 else "Class.dat"
    rows, trailing = read_class_dat(src)
    print(f"Parsed {len(rows)} records, {len(SCHEMA)} fields each, "
          f"{RECORD_SIZE} bytes/record.")
    print("First record:", {k: rows[0][k] for k in ("Index", "Code", "EngName", "MeleMastery")})

    export_tsv(rows, "class_export.tsv")
    rows2 = import_tsv("class_export.tsv")
    write_class_dat("class_roundtrip.dat", rows2, trailing)

    same = filecmp.cmp(src, "class_roundtrip.dat", shallow=False)
    print("Round-trip byte-for-byte identical:", same)
    if not same:
        with open(src, "rb") as f1, open("class_roundtrip.dat", "rb") as f2:
            a, b = f1.read(), f2.read()
        print("original size:", len(a), "roundtrip size:", len(b))
        for i in range(min(len(a), len(b))):
            if a[i] != b[i]:
                print("first differing byte at offset", i, a[i], b[i])
                break
