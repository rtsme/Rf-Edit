"""
Hand-derived schemas for the .dat files the GU 2019 parser has no export for.

Five files in this server's script folder have no matching .txt in the
reference parser, so their layouts were derived here directly from the bytes:
dump a record, find the null-terminated string runs, and check that the
resulting field list adds up to the field count and record size in the file's
own header. Each one is then confirmed the same way every other schema is --
read, re-encode, compare against the original file byte for byte (verify_all.py).

The evidence for each derivation is recorded in its comment. Field *names*
below are descriptive guesses where the purpose isn't obvious; the layout is
what's verified. Renaming a column is safe, changing a type or width is not.
"""


def _index_code_dwords(n, prefix="Val", code="Code"):
    """Index dword + a string[64] key + n dwords -- a common small-table shape."""
    return ([("Index", "dword"), (code, "string[64]")]
            + [("%s%d" % (prefix, i), "dword") for i in range(1, n + 1)])


# schedule.dat -- 198 records, 8 fields, 92 bytes.
# Record 0: dword 0 at offset 0, a 64-byte null-padded name at 4 (Korean text
# in the same non-UTF8 encoding as Class.dat's KorName), then dwords at
# 68/72/76/80/84/88. 4 + 64 + 6*4 = 92, and 1 + 1 + 6 = 8 fields.
SCHEDULE = _index_code_dwords(6, prefix="Val", code="Name")

# CashShop_str.dat -- 1000 records, 11 fields, 104 bytes.
# The reference CashShop_str.txt has Code + 11 dwords (108 bytes, 12 fields);
# this build instead has the leading Index dword and only 9 trailing dwords.
# Record 0: dword 0, "cash001" padded to 64 bytes at offset 4, then nine
# dwords at 68..103 all holding 90. Nine of them matches the nine name slots
# every other _str file carries, so they're numbered the same way.
CASHSHOP_STR = _index_code_dwords(9, prefix="Slot")

# CheckPotionEffect.dat -- 1 record, 25 fields, 220 bytes.
# dword 0; "1" padded to 64 at offset 4; a Korean name padded to 64 at 68;
# dword at 132; then five 16-byte slots at 136..215 that each read
# (dword, dword, dword, float) -- the float positions hold exactly 1.0
# (00 00 80 3f) and -1.0 (00 00 80 bf), which is what fixes the slot
# boundaries; then one trailing dword at 216.
# 4 + 64 + 64 + 4 + 5*16 + 4 = 220, and 1+1+1+1+5*4+1 = 25 fields.
CHECK_POTION_EFFECT = [
    ("Index", "dword"),
    ("Code", "string[64]"),
    ("Name", "string[64]"),
    ("Num", "dword"),
]
for _i in range(1, 6):
    CHECK_POTION_EFFECT += [
        ("Eff%dType" % _i, "dword"),
        ("Eff%dSub" % _i, "dword"),
        ("Eff%dVal" % _i, "dword"),
        ("Eff%dRate" % _i, "float"),
    ]
CHECK_POTION_EFFECT += [("Tail", "dword")]

# Editdata.dat -- 550 records, 62 fields, 2108 bytes. (Dated 2006; the only
# file in the folder not rebuilt with the rest, so it's likely a leftover from
# the original content-editor tooling rather than something the server reads.)
# dword 0; key "BWB0_1" padded to 64 at offset 4 (class code + a suffix, one
# record per class per step); then 30 repeats of (64-byte item code, dword) --
# "iwkna01" at 68 with a dword 1 at 132, "iwswa01" at 136 with a dword at 200,
# and so on at a steady 68-byte stride to the end of the record.
# 4 + 64 + 30*68 = 2108, and 1 + 1 + 60 = 62 fields.
EDITDATA = [("Index", "dword"), ("Code", "string[64]")]
for _i in range(1, 31):
    EDITDATA += [("Item%d" % _i, "string[64]"), ("Flag%d" % _i, "dword")]

# MobMessage_str.dat -- 373 records, 93 fields, 230472 bytes (86 MB total; by
# far the largest file here, which is just what 90 message slots per mob costs).
# dword 0; a 64-byte code at offset 4; a dword at 68; then 90 message slots of
# 2560 bytes each. The slot stride was read straight off the record: the
# non-null runs sit at 72, 2632, 5192, ... exactly 2560 apart, 90 of them, and
# 72 + 90*2560 lands precisely on the end of the record.
# 4 + 64 + 4 + 90*2560 = 230472, and 1 + 1 + 1 + 90 = 93 fields.
MOBMESSAGE_STR = [
    ("Index", "dword"),
    ("Code", "string[64]"),
    ("Num", "dword"),
] + [("Msg%d" % i, "string[2560]") for i in range(1, 91)]


# Keyed by lowercase .dat file name.
HAND_SCHEMAS = {
    "schedule.dat": SCHEDULE,
    "cashshop_str.dat": CASHSHOP_STR,
    "checkpotioneffect.dat": CHECK_POTION_EFFECT,
    "editdata.dat": EDITDATA,
    "mobmessage_str.dat": MOBMESSAGE_STR,
}
