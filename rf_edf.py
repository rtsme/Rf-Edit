"""
Codec for the RF Online client's `.edf` OdinTeam container.

BACKLOG #9 found all 32 client `.edf` files sharing one container and could
not read them; BACKLOG #35 recovered the codec from the client's own decoder
rather than from the ciphertext. The transform below is a transcription of
`RF_Online.bin`'s loader -- see `docs/knowledge/edf-container-format.md` in
the umbrella repo for the disassembly evidence and the exact addresses.

Layout, straight off the client's header reader at `FUN_005cb890`
(0x005cb890), which reads the parts in this order:

    offset 0            29 bytes   ASCII magic "RF Online by OdinTeam s(^O^)z"
    offset 29            4 bytes   <u32 LE> payload length
    offset 33            N bytes   encrypted payload
    offset 33 + N      256 bytes   scrambled key -- a TRAILER, at end of file

That is the whole of the 289-byte overhead BACKLOG #9 measured but could not
account for: 29 + 4 + 256 = 289. The client never compares the magic, it just
skips 29 bytes, which is why the string appears nowhere in the binary.

The key is per file, so this is not the single global keystream BACKLOG #9's
two-file comparison suggested -- but it travels inside the file, so one codec
still opens all 32 with no external secret.

Unscrambling the key (`FUN_005cbb00`) is three passes over the 256 bytes:
alternating subtract/add of a power-of-two table, a full reverse, then a swap
of adjacent byte pairs. Decrypting the payload (`FUN_005cba00`) then walks it
byte by byte, subtracting the key byte at even positions and adding it at odd
ones, indexing the key at `(i + 1) % 256`.

Every step is an exact inverse of a corresponding encode step, so a decode
followed by an encode reproduces the original file byte for byte. `--check`
proves that against real files rather than assuming it.

The decoded payload's *inner* structure varies per table and is not this
module's business: this is the container codec only. See BACKLOG #44.

Usage:
    python rf_edf.py <file.edf> ... --check          # decode+re-encode, diff vs original
    python rf_edf.py <file.edf> --out payload.bin --key-out key.bin
    python rf_edf.py payload.bin --encode --key key.bin --out file.edf

    from rf_edf import decrypt, encrypt
        payload, key = decrypt(open("Item.edf", "rb").read())
        assert encrypt(payload, key) == open("Item.edf", "rb").read()
"""
import argparse
import struct
import sys

MAGIC = b"RF Online by OdinTeam s(^O^)z"
LENGTH_FORMAT = "<I"
KEY_LENGTH = 256
OVERHEAD = len(MAGIC) + struct.calcsize(LENGTH_FORMAT) + KEY_LENGTH  # 289

# The client builds this table on the stack in FUN_005cbb00 as the literal
# bytes 01 02 04 08 10 20 40 80.
_DIGITS = (1, 2, 4, 8, 16, 32, 64, 128)


class EdfError(Exception):
    """Raised when a file is not a well-formed OdinTeam container."""


def _require_key(key):
    key = bytes(key)
    if len(key) != KEY_LENGTH:
        raise EdfError("EDF key must be exactly %d bytes, got %d" % (KEY_LENGTH, len(key)))
    return key


def decode_key(scrambled):
    """Undo the key scrambling -- the client's FUN_005cbb00, in order."""
    key = bytearray(_require_key(scrambled))
    for i in range(KEY_LENGTH):
        digit = _DIGITS[(i + 1) % len(_DIGITS)]
        key[i] = ((key[i] - digit) if i % 2 == 0 else (key[i] + digit)) & 0xFF
    key.reverse()
    for i in range(0, KEY_LENGTH, 2):
        key[i], key[i + 1] = key[i + 1], key[i]
    return bytes(key)


def encode_key(key):
    """Exact inverse of `decode_key` -- the same three passes, run backwards.

    The reverse and the pair swap are involutions, so only the arithmetic pass
    flips sign; running the three in the opposite order is what makes this an
    inverse rather than a second application.
    """
    key = bytearray(_require_key(key))
    for i in range(0, KEY_LENGTH, 2):
        key[i], key[i + 1] = key[i + 1], key[i]
    key.reverse()
    for i in range(KEY_LENGTH):
        digit = _DIGITS[(i + 1) % len(_DIGITS)]
        key[i] = ((key[i] + digit) if i % 2 == 0 else (key[i] - digit)) & 0xFF
    return bytes(key)


def _transform(payload, key, decoding):
    """The client's FUN_005cba00 payload walk, and its inverse.

    Decoding subtracts the key byte at even positions and adds it at odd ones;
    encoding does the opposite. The key index is `(i + 1) % 256`, not `i`.
    """
    out = bytearray(payload)
    for i in range(len(out)):
        k = key[(i + 1) % KEY_LENGTH]
        if (i % 2 == 0) == decoding:
            out[i] = (out[i] - k) & 0xFF
        else:
            out[i] = (out[i] + k) & 0xFF
    return bytes(out)


def decrypt(blob):
    """Return `(payload, key)` for the bytes of a `.edf` file.

    `key` comes back unscrambled, ready to hand straight to `encrypt`.
    """
    if len(blob) < OVERHEAD:
        raise EdfError("file is %d bytes, too small for the %d-byte container overhead"
                       % (len(blob), OVERHEAD))
    if blob[:len(MAGIC)] != MAGIC:
        raise EdfError("not an OdinTeam RF Online container (magic does not match)")

    payload_length = struct.unpack_from(LENGTH_FORMAT, blob, len(MAGIC))[0]
    expected = payload_length + OVERHEAD
    if len(blob) != expected:
        raise EdfError("header declares a %d-byte payload, so the file should be %d bytes, but it is %d"
                       % (payload_length, expected, len(blob)))

    start = len(MAGIC) + struct.calcsize(LENGTH_FORMAT)
    key = decode_key(blob[-KEY_LENGTH:])
    return _transform(blob[start:start + payload_length], key, decoding=True), key


def encrypt(payload, key):
    """Rebuild a `.edf` file from a decoded payload and its decoded key."""
    key = _require_key(key)
    if len(payload) > 0xFFFFFFFF:
        raise EdfError("payload is too large for the container's 32-bit length field")
    return (MAGIC
            + struct.pack(LENGTH_FORMAT, len(payload))
            + _transform(payload, key, decoding=False)
            + encode_key(key))


def decrypt_file(path):
    with open(path, "rb") as f:
        return decrypt(f.read())


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("file", nargs="+",
                        help="the .edf file(s) to read, or the payload to --encode")
    parser.add_argument("--check", action="store_true",
                        help="decode then re-encode each file and diff against the original")
    parser.add_argument("--encode", action="store_true",
                        help="build a .edf from a decoded payload (needs --key)")
    parser.add_argument("--key", help="file holding the 256-byte decoded key, for --encode")
    parser.add_argument("--out", help="write the payload (or the rebuilt .edf) here")
    parser.add_argument("--key-out", help="write the decoded 256-byte key here")
    args = parser.parse_args(argv)

    if args.encode:
        if len(args.file) != 1 or not args.key or not args.out:
            parser.error("--encode takes exactly one payload file, --key and --out")
        with open(args.file[0], "rb") as f:
            payload = f.read()
        with open(args.key, "rb") as f:
            key = f.read()
        with open(args.out, "wb") as f:
            f.write(encrypt(payload, key))
        print("wrote %s" % args.out)
        return 0

    if args.check:
        failures = 0
        for path in args.file:
            with open(path, "rb") as f:
                original = f.read()
            try:
                payload, key = decrypt(original)
            except EdfError as exc:
                print("FAIL   %s: %s" % (path, exc))
                failures += 1
                continue
            if encrypt(payload, key) == original:
                print("OK     %s (%d-byte payload)" % (path, len(payload)))
            else:
                print("FAIL   %s: re-encoding does not reproduce the original bytes" % path)
                failures += 1
        print("\n%d/%d file(s) round-trip byte-exact" % (len(args.file) - failures, len(args.file)))
        return 1 if failures else 0

    if len(args.file) != 1:
        parser.error("pass a single file unless you are using --check")
    payload, key = decrypt_file(args.file[0])
    if args.key_out:
        with open(args.key_out, "wb") as f:
            f.write(key)
    if args.out:
        with open(args.out, "wb") as f:
            f.write(payload)
        print("wrote %d bytes to %s" % (len(payload), args.out))
    else:
        sys.stdout.buffer.write(payload)
    return 0


if __name__ == "__main__":
    sys.exit(main())
