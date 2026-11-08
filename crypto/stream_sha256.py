#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
stream_sha256.py — потоковый шифр вида SHA-256(key || nonce || counter) XOR.

Типовой самодельный «stream»:
    keystream_i = H(key || nonce || counter_be_32)
    plaintext  = ciphertext XOR keystream

  python stream_sha256.py --cipher 4cd2... --key 4530... --nonce dc1e...
  python stream_sha256.py --cipher 4cd2... --key 4530... --nonce dc1e... --brute
  python stream_sha256.py --cipher 4cd2... --key-keyword "hex" --nonce-keyword "hex" --brute

--brute перебирает: hex/base64/raw для key и nonce, counter 4/8 байт,
big/little endian, старт 0/1, sha256/sha1/md5. Печатает варианты, где есть
печатный текст или фигурные скобки.
"""
from __future__ import annotations

# Windows: консоль/pipe не должны падать на Unicode (—, →, «», █).
try:
    import sys as _sys
    for _stream in (_sys.stdout, _sys.stderr):
        _stream.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

import argparse
import base64
import hashlib
import re


def decode_variants(s: str):
    out = [("raw", s.encode())]
    try:
        out.append(("hex", bytes.fromhex(re.sub(r"(?i)0x|[\s:]", "", s))))
    except ValueError:
        pass
    try:
        out.append(("base64", base64.b64decode(s + "=" * (-len(s) % 4))))
    except Exception:
        pass
    return out


def keystream(hash_name, key: bytes, nonce: bytes, length: int,
              counter_size=4, endian="big", start=0):
    h = getattr(hashlib, hash_name)
    out = bytearray()
    i = start
    while len(out) < length:
        ctr = i.to_bytes(counter_size, endian)
        out += h(key + nonce + ctr).digest()
        i += 1
    return bytes(out[:length])


def xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def printable_ratio(b: bytes) -> float:
    if not b:
        return 0
    return sum(32 <= c < 127 or c in (9, 10, 13) for c in b) / len(b)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cipher", required=True, help="hex (по умолчанию)")
    ap.add_argument("--cipher-enc", default="hex", choices=["hex", "base64", "raw"])
    ap.add_argument("--key", required=True)
    ap.add_argument("--nonce", required=True)
    ap.add_argument("--key-enc", choices=["hex", "base64", "raw"])
    ap.add_argument("--nonce-enc", choices=["hex", "base64", "raw"])
    ap.add_argument("--hash", default="sha256", choices=["sha256", "sha1", "md5", "sha512"])
    ap.add_argument("--counter-size", type=int, default=4)
    ap.add_argument("--endian", default="big", choices=["big", "little"])
    ap.add_argument("--start", type=int, default=0)
    ap.add_argument("--brute", action="store_true")
    args = ap.parse_args()

    if args.cipher_enc == "hex":
        cipher = bytes.fromhex(re.sub(r"(?i)0x|[\s:]", "", args.cipher))
    elif args.cipher_enc == "base64":
        cipher = base64.b64decode(args.cipher)
    else:
        cipher = args.cipher.encode()

    keys = decode_variants(args.key) if not args.key_enc else [(args.key_enc, {
        "hex": lambda s: bytes.fromhex(re.sub(r"(?i)0x|[\s:]", "", s)),
        "base64": lambda s: base64.b64decode(s + "=" * (-len(s) % 4)),
        "raw": lambda s: s.encode(),
    }[args.key_enc](args.key))]
    nonces = decode_variants(args.nonce) if not args.nonce_enc else [(args.nonce_enc, {
        "hex": lambda s: bytes.fromhex(re.sub(r"(?i)0x|[\s:]", "", s)),
        "base64": lambda s: base64.b64decode(s + "=" * (-len(s) % 4)),
        "raw": lambda s: s.encode(),
    }[args.nonce_enc](args.nonce))]

    combos = []
    if args.brute:
        for kn, k in keys:
            for nn, n in nonces:
                for hname in ("sha256", "sha1", "md5"):
                    for csize in (4, 8):
                        for endian in ("big", "little"):
                            for start in (0, 1):
                                combos.append((kn, k, nn, n, hname, csize, endian, start))
    else:
        for kn, k in keys:
            for nn, n in nonces:
                combos.append((kn, k, nn, n, args.hash, args.counter_size,
                               args.endian, args.start))

    results = []
    for kn, k, nn, n, hname, csize, endian, start in combos:
        ks = keystream(hname, k, n, len(cipher), csize, endian, start)
        pt = xor(cipher, ks)
        text = pt.decode("utf-8", "replace")
        score = printable_ratio(pt)
        if re.search(r"[A-Za-z]{3,}\{.*\}", text):
            score += 1.0
        results.append((score, kn, nn, hname, csize, endian, start, pt))

    results.sort(key=lambda x: -x[0])
    for score, kn, nn, hname, csize, endian, start, pt in results[:10]:
        print(f"\n[score={score:.2f}] key={kn} nonce={nn} {hname} ctr={csize}{endian} start={start}")
        print("  hex:", pt[:64].hex())
        print("  txt:", pt.decode("utf-8", "replace")[:300])


if __name__ == "__main__":
    main()
