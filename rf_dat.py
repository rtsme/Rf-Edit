"""
Generic reader/writer for RF Online server-side .dat files (AoP 4.15 build).

Every .dat in Zoneserver\\RF_Bin\\script shares one container format -- this was
verified by checking all 150 of them: a 12-byte header of three little-endian
uint32s (record_count, field_count, record_size) followed by record_count
fixed-width records, with 12 + count*record_size == file size holding exactly
in every case, no trailing bytes anywhere.

So the only per-file unknown is the field layout, and even that is heavily
constrained: the header gives the field count and the record size, so a
candidate schema either adds up to those two numbers or it's wrong. That check
is what verify_schema() does, and it's the reason a wrong schema fails loudly
instead of silently shredding a file on write-back.

Schemas come from the GU 2019 parser's pre-extracted .txt exports (a type row
plus a field-name row -- see schema_from_txt), or are auto-derived for the
uniform _str files (see auto_schema). Type sizes come from that parser's own
include.php type table, reproduced in TYPES below.

Types this build's files actually use are decoded to numbers and strings.
Anything else (the parser's composite pseudo-types like store/stb/spcode) is
carried as a raw hex blob, which still round-trips byte-for-byte -- it just
isn't broken into readable subfields.

Usage:
    python rf_dat.py <File.dat>              read + report + round-trip check
    python rf_dat.py <File.dat> --csv out.csv    also export a CSV

    from rf_dat import Table
        t = Table.open("Class.dat")          # finds a schema automatically
        t.export_csv("class.csv")            # edit in Excel or an IDE
        t.import_csv("class.csv")
        t.save("Class.dat")                  # refuses to write a bad schema
"""
import csv
import json
import os
import re
import struct
import sys

try:
    from schemas_extra import HAND_SCHEMAS
except ImportError:      # usable standalone, just without the hand-derived five
    HAND_SCHEMAS = {}

HEADER_FMT = "<3I"
HEADER_SIZE = 12

# Where the GU 2019 parser's pre-extracted schema exports live. Override with
# the RF_PARSER_DIR environment variable if you move it.
PARSER_DIR = os.environ.get(
    "RF_PARSER_DIR",
    r"C:\Users\Me\Downloads\Parser_GU_Clean_English_Fixed_2019\gu_in",
)

# type name -> (size in bytes, struct code or None for "raw hex blob")
# Sizes are lifted from the GU parser's include.php $types table so our
# layout arithmetic matches the tool that produced the schema exports.
# Signedness follows that table too: dword/long/word/byte are signed there,
# which is what makes the -1 "empty slot" sentinels read as -1 rather than
# 4294967295.
TYPES = {
    "dword":    (4, "<i"),
    "long":     (4, "<i"),
    "word":     (2, "<h"),
    "byte":     (1, "<b"),
    "float":    (4, "<f"),
    "double":   (8, "<d"),
    "udword":   (4, "<I"),
    "uword":    (2, "<H"),
    "ubyte":    (1, "<B"),
    "hex":      (4, "<I"),
    "xeh":      (4, "<I"),
    "xeh64":    (8, "<Q"),
    "qword":    (8, "<Q"),
    "clcode":   (4, None),
    "exclcode": (8, None),
    "ccode":    (4, None),
    "store":    (8, None),
    "bulltype": (11, None),
    "bttype":   (8, None),
    "effbttype": (4, None),
    "stb":      (8, None),
    "stb4":     (4, None),
    "stb12":    (12, None),
    "stb16":    (16, None),
    "res":      (52, None),
    "param1":   (12, None),
    "qitid":    (4, None),
    "lqitem":   (4, None),
    "qcode":    (4, None),
    "spcode":   (8, None),
}

# Zero-width entries in the parser's table: markers for its own display logic,
# not real on-disk fields. A schema containing one can't be laid out.
ZERO_WIDTH = {"param2", "text"}

_STRING_RE = re.compile(r"^string\[(\d+)\]$", re.IGNORECASE)


class SchemaError(Exception):
    pass


def field_size(ftype):
    m = _STRING_RE.match(ftype)
    if m:
        return int(m.group(1))
    if ftype in ZERO_WIDTH:
        raise SchemaError(
            "field type %r has no fixed width in the reference parser -- "
            "this schema can't be used for binary layout" % ftype
        )
    if ftype not in TYPES:
        raise SchemaError("unknown field type %r" % ftype)
    return TYPES[ftype][0]


def record_size(schema):
    return sum(field_size(t) for _, t in schema)


# --------------------------------------------------------------------------
# codecs
# --------------------------------------------------------------------------

def decode(raw, ftype):
    m = _STRING_RE.match(ftype)
    if m:
        # latin-1 is a lossless 1:1 byte<->char mapping, so this round-trips
        # ANY byte sequence exactly -- including the Korean (non-UTF8) bytes in
        # KorName -- even though those won't display as readable Korean in the
        # CSV. Don't "fix" this to utf-8/cp949 without changing encode() to
        # match, or write-back will corrupt those fields.
        return raw.split(b"\x00", 1)[0].decode("latin-1")
    code = TYPES[ftype][1]
    if code is None:
        return raw.hex().upper()      # composite type: carry the bytes as-is
    return struct.unpack(code, raw)[0]


_ESCAPE_RE = re.compile(r"\\(\\|x[0-9a-fA-F]{2})")


def escape_text(s):
    """Render a field value as pure ASCII, escaping anything else as \\xNN.

    The string fields hold raw bytes decoded as latin-1, so ~94k of them across
    these files are above 0x7F (the Korean text). Writing those to a text file
    as-is means every tool that touches it -- editor, git, terminal -- has an
    opinion about the encoding, and exactly one of them re-encoding is silent
    corruption of a field nobody edited. Escaping sidesteps that entirely: the
    CSVs are 7-bit ASCII, so there is nothing to re-encode. It costs no
    readability, because those fields don't display as Korean anyway.
    """
    out = []
    for ch in s:
        o = ord(ch)
        if ch == "\\":
            out.append("\\\\")
        elif 32 <= o <= 126:
            out.append(ch)
        else:
            out.append("\\x%02x" % o)
    return "".join(out)


def unescape_text(s):
    """Inverse of escape_text. Raises ValueError on a malformed escape."""
    out = []
    i = 0
    while i < len(s):
        ch = s[i]
        if ch != "\\":
            out.append(ch)
            i += 1
            continue
        m = _ESCAPE_RE.match(s, i)
        if not m:
            raise ValueError(
                "bad escape at position %d: expected \\\\ or \\xNN, got %r"
                % (i, s[i:i + 4]))
        tok = m.group(1)
        out.append("\\" if tok == "\\" else chr(int(tok[1:], 16)))
        i = m.end()
    return "".join(out)


def parse_value(text, ftype):
    """Turn user-entered text into a value of the right Python type for ftype.

    Raises ValueError with a message worth showing to a person. Shared by the
    CSV importer and the GUI so both accept and reject exactly the same input.
    """
    m = _STRING_RE.match(ftype)
    if m:
        width = int(m.group(1))
        try:
            raw = text.encode("latin-1")
        except UnicodeEncodeError:
            raise ValueError(
                "contains characters this file's encoding can't store "
                "(latin-1 only; paste plain text)")
        if len(raw) > width:
            raise ValueError("too long: %d bytes, field holds %d"
                             % (len(raw), width))
        return text
    size, code = TYPES[ftype]
    if code is None:
        cleaned = text.strip().replace(" ", "")
        try:
            raw = bytes.fromhex(cleaned)
        except ValueError:
            raise ValueError("%s expects hex digits" % ftype)
        if len(raw) != size:
            raise ValueError("%s needs exactly %d bytes of hex (%d digits), "
                             "got %d" % (ftype, size, size * 2, len(raw)))
        return cleaned.upper()
    if code in ("<f", "<d"):
        try:
            return float(text)
        except ValueError:
            raise ValueError("expects a number")
    try:
        value = int(text)
    except ValueError:
        raise ValueError("expects a whole number")
    # Range-check here rather than letting struct.error surface at save time,
    # when the offending field is no longer on screen.
    try:
        struct.pack(code, value)
    except struct.error:
        raise ValueError("%d is out of range for %s" % (value, ftype))
    return value


def encode(value, ftype):
    m = _STRING_RE.match(ftype)
    if m:
        width = int(m.group(1))
        b = str(value).encode("latin-1")[:width]
        return b + b"\x00" * (width - len(b))
    size, code = TYPES[ftype]
    if code is None:
        b = bytes.fromhex(str(value))
        if len(b) != size:
            raise ValueError(
                "%s field needs %d bytes of hex, got %d" % (ftype, size, len(b))
            )
        return b
    if code in ("<f", "<d"):
        return struct.pack(code, float(value))
    return struct.pack(code, int(value))


# --------------------------------------------------------------------------
# schema sources
# --------------------------------------------------------------------------

def uniquify(schema):
    """Make field names unique, suffixing repeats with _2, _3, ...

    Several reference schemas reuse one name across a repeated group -- PcRoom
    has ten fields called itmFix, CombineTable has twenty-four called
    ResultItem. Rows are keyed by name, so leaving duplicates in place means
    later fields silently overwrite earlier ones and write-back fills the whole
    group with the last field's value. Renaming them keeps every field
    addressable and keeps the CSV columns distinct.
    """
    seen, out = {}, []
    for name, ftype in schema:
        if name in seen:
            seen[name] += 1
            new = "%s_%d" % (name, seen[name])
            while new in seen:
                seen[name] += 1
                new = "%s_%d" % (name, seen[name])
            seen[new] = 1
            name = new
        else:
            seen[name] = 1
        out.append((name, ftype))
    return out


def schema_from_txt(txt_path):
    """Parse a GU-parser .txt export's first two lines into [(name, type)].

    Line 1 is the type row, line 2 the field-name row. A trailing 'END' token
    marks the end of the row rather than a field.
    """
    with open(txt_path, "r", encoding="latin-1") as f:
        types = f.readline().rstrip("\n\r").split("\t")
        names = f.readline().rstrip("\n\r").split("\t")
    while types and types[-1].strip().upper() in ("", "END"):
        types.pop()
    schema = []
    for i, t in enumerate(types):
        t = t.strip()
        name = names[i].strip() if i < len(names) else ""
        schema.append((name or "field%d" % i, t))
    return uniquify(schema)


def find_txt_schema(dat_name, parser_dir=PARSER_DIR):
    """Locate the parser's .txt export matching a .dat file name, if any."""
    want = os.path.splitext(os.path.basename(dat_name))[0].lower() + ".txt"
    if not os.path.isdir(parser_dir):
        return None
    for root, _dirs, files in os.walk(parser_dir):
        for fn in files:
            if fn.lower() == want:
                return os.path.join(root, fn)
    return None


def write_schema_json(schema, path, dat_name="", source="",
                      header_field_count=None):
    """Freeze a schema to JSON so a repo doesn't depend on the parser folder.

    The reference .txt exports live in a Downloads folder that could disappear
    at any time; a checkout that can't rebuild its own .dat files is not much
    of a backup. Everything needed to write the file is here -- the field order
    and types give both the header's field count and its record size.
    """
    doc = {
        "dat": dat_name,
        "schema_source": source,
        "field_count": len(schema),
        # What the .dat's own header says. Usually the same, but the per-map
        # tables disagree, and the rebuilt file has to carry their value back
        # unchanged or it isn't the same file.
        "header_field_count": len(schema) if header_field_count is None
                              else header_field_count,
        "record_size": record_size(schema),
        "fields": [{"name": n, "type": t} for n, t in schema],
    }
    # newline="\n" explicitly: on Windows the default would write CRLF, and
    # then every checkout on another machine rewrites all 155 files.
    with open(path, "w", encoding="ascii", newline="\n") as f:
        json.dump(doc, f, indent=1)
        f.write("\n")


def read_schema_json(path):
    with open(path, "r", encoding="ascii") as f:
        doc = json.load(f)
    schema = [(fld["name"], fld["type"]) for fld in doc["fields"]]
    # The stored totals are redundant with the field list on purpose: if a
    # hand-edit to the JSON breaks the layout, it gets caught here rather than
    # producing a plausible-looking but wrong .dat.
    if len(schema) != doc["field_count"] or record_size(schema) != doc["record_size"]:
        raise SchemaError(
            "%s is inconsistent: fields list gives %d fields / %d bytes, "
            "header says %d / %d"
            % (os.path.basename(path), len(schema), record_size(schema),
               doc["field_count"], doc["record_size"]))
    return schema, doc


def auto_schema(field_count, rec_size):
    """Derive a schema from the header alone, for files with no .txt export.

    Only solvable when the record is one leading dword followed by uniform
    string[64] slots -- which is exactly the shape every _str.dat file has.
    Returns None when the header doesn't fit that shape; the caller should
    then report the file as needing a hand-derived schema rather than guess.
    """
    body = rec_size - 4
    if body <= 0 or body % 64 or (body // 64) + 1 != field_count:
        return None
    n = body // 64
    schema = [("Index", "dword"), ("Code", "string[64]")]
    schema += [("Name%d" % i, "string[64]") for i in range(1, n)]
    return schema


def _looks_like_string_slot(records, pos, width, ascii_only=False):
    """True if [pos, pos+width) behaves like a null-padded string in every record.

    That means: printable-or-high bytes up to the first NUL, then nothing but
    NULs to the end of the slot. Control bytes disqualify it, high bytes don't
    -- the legacy Korean text is all high bytes.

    An all-zero region is deliberately NOT accepted: zero bytes are equally
    valid as an empty string or as zeroed numbers, and calling it a string on
    no evidence would hide editable numeric fields behind a blank text column.
    At least one record has to actually contain text.

    A record whose slot is nothing but one repeated byte >= 0x80 (no NUL
    anywhere in it) doesn't count as that evidence either -- that's the
    client's empty-slot fill (e.g. 64 bytes of 0xFF), not text, and unlike a
    real high-byte name it never carries a terminator (BACKLOG #47). A slot
    still reads as a string if some *other* record in it has real text; this
    only stops fill runs from manufacturing text evidence on their own.

    `ascii_only` additionally rejects high bytes. It exists for narrow slots
    (see infer_schema): in four bytes, "no control characters" is nearly no
    evidence at all, and the client's -1 sentinel -- four 0xFF bytes with no
    terminator -- passes the relaxed test in every record. Requiring plain
    printable ASCII is the difference between finding item codes and labelling
    every empty slot in the file as text.
    """
    saw_text = False
    for rec in records:
        slot = rec[pos:pos + width]
        if len(slot) < width:
            return False
        if len(set(slot)) == 1 and slot[0] >= 0x80:
            continue                          # fill run: not text, not disqualifying
        head, _sep, tail = slot.partition(b"\x00")
        if tail.strip(b"\x00"):
            return False                      # data after the terminator
        if any(b < 0x20 for b in head):
            return False                      # control bytes: not text
        if ascii_only and any(b > 0x7e for b in head):
            return False                      # high bytes: a sentinel, not a code
        if head:
            saw_text = True
    return saw_text


# Below this width a slot carries too little evidence to be called text on the
# relaxed rule -- see _looks_like_string_slot's `ascii_only`.
NARROW_STRING_WIDTH = 8


def infer_schema(records, rec_size, width=64, string_widths=None,
                 allow_short_numbers=False):
    """Work out a layout from the record bytes themselves.

    For the thousands of per-map tables there is no reference schema anywhere,
    so the alternative to this is treating them as opaque. The rule is simple
    and evidence-driven: walk the record, and take a string slot wherever the
    bytes across every record actually behave like one, otherwise take a
    4-byte number.

    Byte-exactness is guaranteed either way -- both readings re-encode to the
    same bytes -- so what this buys is *labels*: text shows up as text instead
    of sixteen meaningless integers.

    Two knobs exist for the client's `.edf` tables (BACKLOG #44), both off by
    default so server `.dat` inference keeps its historical behaviour:

    `string_widths` offers more than one string width. Candidates are tried
    **widest first**: a 64-byte name would otherwise be chopped into a 4-byte
    "code" by its own first four characters, since those carry no terminator
    and so pass the narrow test trivially. A genuine 4-byte code slot can
    never be mistaken for a 64-byte one in the other direction -- whatever
    follows it inside the 64-byte window puts data after the terminator.

    Candidates narrower than `NARROW_STRING_WIDTH` are also held to plain
    printable ASCII, because the relaxed rule that works on a 64-byte name
    slot accepts almost anything in four bytes. Measured over the 17 chain
    files, that one condition cuts the share of "string" values that are
    neither text nor empty from 56% to 13%.

    `allow_short_numbers` lets a record end in a 2- or 1-byte number. Client
    record sizes are not all multiples of four (`Character.edf`'s fifth table
    is 46 bytes), and without this such a table cannot be laid out at all.
    """
    fields = [("Index", "dword")]
    pos = 4
    nstr = nnum = 0
    widths = tuple(sorted(set(string_widths or (width,)), reverse=True))
    while pos < rec_size:
        slot = next((w for w in widths
                     if pos + w <= rec_size
                     and _looks_like_string_slot(
                         records, pos, w, ascii_only=w < NARROW_STRING_WIDTH)),
                    None)
        if slot is not None:
            nstr += 1
            fields.append(("Text%d" % nstr if nstr > 1 else "Code",
                           "string[%d]" % slot))
            pos += slot
        elif pos + 4 <= rec_size:
            nnum += 1
            fields.append(("Val%d" % nnum, "dword"))
            pos += 4
        elif allow_short_numbers and pos + 2 <= rec_size:
            nnum += 1
            fields.append(("Val%d" % nnum, "word"))
            pos += 2
        elif allow_short_numbers and pos + 1 <= rec_size:
            nnum += 1
            fields.append(("Val%d" % nnum, "byte"))
            pos += 1
        else:
            raise SchemaError(
                "record size %d leaves %d trailing byte(s) that fit no field"
                % (rec_size, rec_size - pos))
    return fields


def fit_schema(schema, field_count, rec_size):
    """Reconcile a reference schema against this build's actual header.

    This server's files carry a leading sequential 'Index' dword that the 2019
    reference schemas don't have, so a schema that is short by exactly one
    field and four bytes gets that column restored. Anything else is left
    alone and will be caught by verify_schema.
    """
    if len(schema) == field_count and record_size(schema) == rec_size:
        return schema, "exact"
    if len(schema) + 1 == field_count and record_size(schema) + 4 == rec_size:
        return [("Index", "dword")] + schema, "index-prepended"
    return schema, "mismatch"


def verify_schema(schema, field_count, rec_size, check_field_count=True):
    """Raise unless the schema matches the header's record size (and field count).

    record_size is the authoritative number: it fixes the layout, and getting it
    wrong shifts every field. field_count is only a cross-check, and on the
    per-map tables it can't even be that -- 2347 of them declare 1 field for a
    record that plainly holds 8. Those files are read with check_field_count
    off, and their original header value is written back untouched.
    """
    names = [n for n, _ in schema]
    if len(set(names)) != len(names):
        dups = sorted({n for n in names if names.count(n) > 1})
        raise SchemaError(
            "schema has duplicate field names %s -- rows are keyed by name, so "
            "duplicates would collapse into one value and corrupt the repeated "
            "group on write. Run the schema through uniquify()." % dups)
    n, size = len(schema), record_size(schema)
    if size != rec_size or (check_field_count and n != field_count):
        raise SchemaError(
            "schema does not match this file: header says %d fields / %d bytes "
            "per record, schema has %d fields / %d bytes. Do not write with "
            "this schema -- it would corrupt the file."
            % (field_count, rec_size, n, size)
        )


# --------------------------------------------------------------------------
# table
# --------------------------------------------------------------------------

class Table(object):
    def __init__(self, schema, rows, field_count, rec_size, source=None,
                 schema_source=None, strict_field_count=True):
        self.schema = schema
        self.rows = rows
        # The header's own field_count, written back verbatim -- see
        # verify_schema for why it isn't always len(schema).
        self.field_count = field_count
        self.rec_size = rec_size
        self.source = source
        self.schema_source = schema_source
        self.strict_field_count = strict_field_count

    @classmethod
    def header_of(cls, path):
        with open(path, "rb") as f:
            head = f.read(HEADER_SIZE)
        if len(head) < HEADER_SIZE:
            raise SchemaError("%s is too small to hold a header" % path)
        return struct.unpack(HEADER_FMT, head)

    @classmethod
    def open(cls, path, schema=None, parser_dir=PARSER_DIR):
        """Read a .dat, finding a schema automatically when one isn't given."""
        with open(path, "rb") as f:
            data = f.read()
        count, field_count, rec_size = struct.unpack_from(HEADER_FMT, data, 0)
        expected = HEADER_SIZE + count * rec_size
        if expected != len(data):
            raise SchemaError(
                "%s: header implies %d bytes (12 + %d records x %d) but the "
                "file is %d bytes -- not the standard container format"
                % (path, expected, count, rec_size, len(data))
            )

        schema_source = "caller-supplied"
        strict = True
        if schema is None:
            hand = HAND_SCHEMAS.get(os.path.basename(path).lower())
            if hand is not None:
                schema, schema_source = hand, "hand-derived (schemas_extra)"
        if schema is None:
            txt = find_txt_schema(path, parser_dir)
            if txt:
                schema, how = fit_schema(
                    schema_from_txt(txt), field_count, rec_size)
                schema_source = "%s (%s)" % (os.path.basename(txt), how)
            if schema is None or len(schema) != field_count \
                    or record_size(schema) != rec_size:
                auto = auto_schema(field_count, rec_size)
                if auto is not None:
                    schema, schema_source = auto, "auto-derived (_str shape)"
            if schema is None or record_size(schema) != rec_size:
                # Last resort: read the layout off the records themselves.
                # Used by the per-map tables, which no reference covers.
                if count == 0:
                    # An empty table has no bytes to infer from, but it also
                    # has no bytes to get wrong: the whole file is its header.
                    # A placeholder of the right record size rebuilds it
                    # exactly and keeps it under version control. The column
                    # names are meaningless -- if you ever add a row here,
                    # derive the real layout first.
                    if rec_size % 4:
                        raise SchemaError(
                            "%s: empty table whose %d-byte record isn't a "
                            "whole number of dwords -- no safe placeholder"
                            % (path, rec_size))
                    schema = [("Val%d" % (i + 1), "dword")
                              for i in range(rec_size // 4)]
                    schema_source = "placeholder (empty table)"
                    strict = False
                    verify_schema(schema, field_count, rec_size,
                                  check_field_count=False)
                    return cls(schema, [], field_count, rec_size, path,
                               schema_source, strict_field_count=False)
                sample = [data[HEADER_SIZE + i * rec_size:
                               HEADER_SIZE + (i + 1) * rec_size]
                          for i in range(min(count, 200))]
                schema = infer_schema(sample, rec_size)
                schema_source = "inferred from records"
                strict = False
        verify_schema(schema, field_count, rec_size,
                      check_field_count=strict)

        rows = []
        offset = HEADER_SIZE
        for _ in range(count):
            row, pos = {}, offset
            for name, ftype in schema:
                w = field_size(ftype)
                row[name] = decode(data[pos:pos + w], ftype)
                pos += w
            rows.append(row)
            offset += rec_size
        return cls(schema, rows, field_count, rec_size, path, schema_source,
                   strict_field_count=strict)

    @classmethod
    def from_csv(cls, csv_path, schema, field_count=None):
        """Build a table from a CSV plus its frozen schema -- no .dat needed.

        The record count comes from the number of CSV rows, and the header's
        other two numbers come from the schema, so adding or deleting rows in
        the CSV adds or deletes records in the rebuilt file.
        """
        t = cls(schema, [], field_count if field_count is not None else len(schema),
                record_size(schema), source=None,
                schema_source=os.path.basename(csv_path),
                strict_field_count=field_count is None)
        t.import_csv(csv_path)
        return t

    def to_bytes(self):
        verify_schema(self.schema, self.field_count, self.rec_size,
                      check_field_count=self.strict_field_count)
        out = bytearray(struct.pack(
            HEADER_FMT, len(self.rows), self.field_count, self.rec_size))
        for row in self.rows:
            for name, ftype in self.schema:
                out += encode(row[name], ftype)
        return bytes(out)

    def save(self, path):
        blob = self.to_bytes()
        with open(path, "wb") as f:
            f.write(blob)

    def export_csv(self, path):
        """Write one line per record, ASCII-only, LF endings.

        lineterminator is pinned to "\\n" so the same file comes out of Windows
        and Linux identically -- otherwise git sees every line as changed the
        first time the other platform touches it.
        """
        names = [n for n, _ in self.schema]
        with open(path, "w", newline="", encoding="ascii") as f:
            w = csv.writer(f, lineterminator="\n")
            w.writerow(names)
            for row in self.rows:
                w.writerow([escape_text(str(row[n])) for n in names])

    def import_csv(self, path):
        with open(path, "r", newline="", encoding="ascii") as f:
            reader = csv.reader(f)
            try:
                header = next(reader)
            except StopIteration:
                raise ValueError("%s is empty" % os.path.basename(path))
            expected = [n for n, _ in self.schema]
            if header != expected:
                raise ValueError(
                    "%s: columns don't match the schema.\nexpected %d columns "
                    "starting %s\ngot %d columns starting %s\nColumns must not "
                    "be added, removed or reordered -- they are the record "
                    "layout." % (os.path.basename(path), len(expected),
                                 expected[:4], len(header), header[:4]))
            rows = []
            for i, rec in enumerate(reader):
                if len(rec) != len(expected):
                    raise ValueError(
                        "%s line %d: has %d values, expected %d"
                        % (os.path.basename(path), i + 2, len(rec),
                           len(expected)))
                row = {}
                for (name, ftype), text in zip(self.schema, rec):
                    try:
                        row[name] = parse_value(unescape_text(text), ftype)
                    except ValueError as e:
                        raise ValueError("%s line %d, column %s: %s"
                                         % (os.path.basename(path), i + 2,
                                            name, e))
                rows.append(row)
        self.rows = rows
        return rows

    def roundtrip_ok(self):
        """True when re-encoding the parsed rows reproduces the source file."""
        if not self.source:
            return None
        with open(self.source, "rb") as f:
            return f.read() == self.to_bytes()


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 2
    path = argv[1]
    t = Table.open(path)
    print("%s: %d records x %d fields x %d bytes"
          % (os.path.basename(path), len(t.rows), t.field_count, t.rec_size))
    print("schema: %s" % t.schema_source)
    if t.rows:
        preview = list(t.rows[0].items())[:6]
        print("first record: %s" % ", ".join("%s=%r" % kv for kv in preview))
    print("round-trip byte-identical: %s" % t.roundtrip_ok())
    if "--csv" in argv:
        out = argv[argv.index("--csv") + 1]
        t.export_csv(out)
        print("wrote %s" % out)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
