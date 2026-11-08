#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
xor_scan.py — найти XOR-ключ по файлу.

  python xor_scan.py bin
  python xor_scan.py bin --keylen 8
  python xor_scan.py bin --known "This is" --keylen 5
  python xor_scan.py enc.bin --offset 1024 --length 4096

Режимы:
  * одиночный байт: перебор 1..255 по печатности и частым словам;
  * повторяющийся ключ: для каждой позиции выбирается байт, дающий максимум
    печатных символов (быстро и работает на тексте);
  * known plaintext: ключ восстанавливается точно по префиксу.
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
from collections import Counter

COMMON = [b"the", b"and", b"flag", b"ctf", b"this", b"key", b"secret", b"password"]


def printable_ratio(b: bytes) -> float:
    if not b:
        return 0.0
    return sum(32 <= c < 127 or c in (9, 10, 13) for c in b) / len(b)


def score(b: bytes) -> float:
    low = b.lower()
    words = sum(low.count(w) for w in COMMON)
    return printable_ratio(b) + words * 0.05


def single_byte(data: bytes, top=10):
    res = []
    for k in range(1, 256):
        dec = bytes(c ^ k for c in data)
        res.append((score(dec), k, dec))
    res.sort(key=lambda x: -x[0])
    return res[:top]


def repeating(data: bytes, keylen: int):
    key = bytearray()
    for i in range(keylen):
        col = data[i::keylen]
        best_k, best_s = 0, -1
        for k in range(256):
            s = printable_ratio(bytes(c ^ k for c in col))
            if s > best_s:
                best_s, best_k = s, k
        key.append(best_k)
    dec = bytes(c ^ key[i % keylen] for i, c in enumerate(data))
    return bytes(key), dec


def known_prefix(data: bytes, known: bytes, keylen: int):
    key = bytearray(keylen)
    counts = [0] * keylen
    for i, p in enumerate(known):
        if i >= len(data):
            break
        k = data[i] ^ p
        pos = i % keylen
        if counts[pos] == 0:
            key[pos] = k
            counts[pos] = 1
        elif key[pos] != k:
            return None
    if any(c == 0 for c in counts):
        return None
    return bytes(key), bytes(c ^ key[i % keylen] for i, c in enumerate(data))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("file")
    ap.add_argument("--keylen", type=int)
    ap.add_argument("--known")
    ap.add_argument("--offset", type=int, default=0)
    ap.add_argument("--length", type=int, default=0)
    ap.add_argument("--top", type=int, default=10)
    ap.add_argument("--min-score", type=float, default=0.5)
    args = ap.parse_args()

    data = open(args.file, "rb").read()
    if args.offset or args.length:
        data = data[args.offset:args.offset + (args.length or None)]

    if args.known and args.keylen:
        r = known_prefix(data, args.known.encode(), args.keylen)
        if r:
            key, dec = r
            print(f"[+] key: {key!r}")
            print(f"[+] text: {dec[:300]!r}")
        else:
            print("[-] known-префикс не сходится с этой длиной ключа")
        return

    if args.keylen:
        key, dec = repeating(data, args.keylen)
        print(f"[+] key ({args.keylen}): {key!r}  hex={key.hex()}")
        print(f"[+] text: {dec[:400]!r}")
        return

    print("[+] одиночный байт, топ кандидатов:")
    for s, k, dec in single_byte(data, args.top):
        if s < args.min_score:
            continue
        print(f"  key=0x{k:02x} ({k:3d}) score={s:.2f}  {dec[:120]!r}")


if __name__ == "__main__":
    try:
        main()
    except (FileNotFoundError, IsADirectoryError, PermissionError) as e:
        print(f"[-] не могу открыть: {getattr(e, 'filename', None) or e}")
    except BrokenPipeError:
        pass
    except KeyboardInterrupt:
        print("\n[-] прервано")
