"""
XOR codec for RF Online client text files hidden behind a single-byte XOR.

BACKLOG #9 found three files under `DataTable/en-ph` that are ordinary CRLF
text obfuscated with a constant single-byte XOR: `Apa.dic`, `Ipa.dic`, and
`Cepa.env`, all under key 0xB5 (the profanity filter's word list, banned
name list, and its config). XOR is an involution, so decode and encode are
the same operation -- applying the key twice returns the original bytes
byte-for-byte, with no schema to get wrong.

`System/idll.rdt` uses a different key (0x07) but is deliberately NOT
covered here (BACKLOG #36, James 2026-08-27 B1/C1): it sits next to the
anti-cheat stack, which is not a good place to be changing formats, and
stays verbatim.

Usage:
    python rf_xor.py <file> [--key 0xB5] --out <out>   # decode/encode (same op)
    python rf_xor.py <file> [--key 0xB5] --check       # apply key twice, diff vs original

    from rf_xor import xor_bytes
        xor_bytes(data, 0xB5)
"""
import argparse
import os
import sys

DIC_ENV_KEY = 0xB5

# Keys proven in BACKLOG #9 for the files this codec covers. idll.rdt (0x07)
# is intentionally absent -- BACKLOG #36 leaves it verbatim.
KNOWN_FILES = {
    "Apa.dic": DIC_ENV_KEY,
    "Ipa.dic": DIC_ENV_KEY,
    "Cepa.env": DIC_ENV_KEY,
}


def xor_bytes(data, key):
    """XOR every byte of `data` with the single-byte `key`.

    Involution: xor_bytes(xor_bytes(data, key), key) == data.
    """
    return bytes(b ^ key for b in data)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("file")
    parser.add_argument("--key", help="single-byte XOR key, e.g. 0xB5 (defaults to the known key for named files)")
    parser.add_argument("--out", help="write the transformed bytes here")
    parser.add_argument("--check", action="store_true", help="apply the key twice and diff against the original")
    args = parser.parse_args(argv)

    name = os.path.basename(args.file)
    if args.key:
        key = int(args.key, 0)
    elif name in KNOWN_FILES:
        key = KNOWN_FILES[name]
    else:
        parser.error(f"no known key for {name!r} -- pass --key")

    with open(args.file, "rb") as f:
        original = f.read()

    decoded = xor_bytes(original, key)

    if args.check:
        roundtrip = xor_bytes(decoded, key)
        if roundtrip == original:
            print(f"OK: {args.file} round-trips byte-exact under key {hex(key)}")
        else:
            print(f"MISMATCH: {args.file} does NOT round-trip under key {hex(key)}")
            sys.exit(1)
        return

    if args.out:
        with open(args.out, "wb") as f:
            f.write(decoded)
        print(f"wrote {len(decoded)} bytes to {args.out}")
    else:
        sys.stdout.buffer.write(decoded)


if __name__ == "__main__":
    main()
