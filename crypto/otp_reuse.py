#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
otp_reuse.py — два шифротекста с одинаковым потоком (two-time pad).

  python otp_reuse.py --c1 <hex> --c2 <hex>
  python otp_reuse.py --c1 ... --c2 ... --crib "the "
  python otp_reuse.py --c1 ... --c2 ... --crib "flag{" --min-printable 0.8

Работает, когда один и тот же keystream использован дважды:
    c1 ^ c2 = p1 ^ p2
Дальше подставляем известное слово (crib) в p1 и смотрим, получается ли
осмысленный p2 на этом месте.
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
import re


def printable_ratio(b: bytes) -> float:
    if not b:
        return 0.0
    return sum(32 <= c < 127 or c in (9, 10, 13) for c in b) / len(b)


def xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--c1", required=True, help="hex или файл с hex")
    ap.add_argument("--c2", required=True)
    ap.add_argument("--crib")
    ap.add_argument("--min-printable", type=float, default=0.75)
    args = ap.parse_args()

    def load(s):
        try:
            return bytes.fromhex(re.sub(r"(?i)0x|[\s:]", "", s))
        except ValueError:
            return bytes.fromhex(re.sub(r"(?i)0x|[\s:]", "", open(s).read()))

    c1, c2 = load(args.c1), load(args.c2)
    n = min(len(c1), len(c2))
    x = xor(c1[:n], c2[:n])
    print(f"[+] длина: {n}")
    print("[+] c1^c2 (печатное):")
    print("".join(chr(c) if 32 <= c < 127 else "." for c in x))

    if not args.crib:
        return
    crib = args.crib.encode()
    print(f"\n[+] ищу crib {crib!r}:")
    found = 0
    for i in range(0, n - len(crib) + 1):
        p2 = xor(x[i:i + len(crib)], crib)
        if printable_ratio(p2) >= args.min_printable:
            found += 1
            ctx_lo = max(0, i - 20)
            ctx_hi = min(n, i + len(crib) + 20)
            print(f"  pos={i}: p1={crib!r}  p2={p2!r}")
            print(f"        контекст p1^p2: "
                  f"{''.join(chr(c) if 32 <= c < 127 else '.' for c in x[ctx_lo:ctx_hi])}")
    if not found:
        print("  [-] совпадений нет; попробуй другой crib или проверь, что поток общий")


if __name__ == "__main__":
    main()
