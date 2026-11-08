#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
prng_seed.py — предсказание Python random по seed (timestamp):
JWT-секреты и пароли, зависящие от времени старта.

  python prng_seed.py --ts "2025-01-01 12:00:00" --range 10
  python prng_seed.py --unix 1735732800 --range 5 --len 32
  python prng_seed.py --ts "2025-01-01 12:00:00" --alphabet alnum --len 16
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
import datetime as dt
import random
import string

ALPHABETS = {
    "upper": string.ascii_uppercase,
    "upperdigits": string.ascii_uppercase + string.digits,
    "alnum": string.ascii_letters + string.digits,
    "digits": string.digits,
}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ts", help='строка времени, например "2025-01-01 12:00:00" (UTC)')
    ap.add_argument("--unix", type=int)
    ap.add_argument("--range", type=int, default=10, help="± секунд")
    ap.add_argument("--len", type=int, default=32)
    ap.add_argument("--alphabet", default="upperdigits", choices=list(ALPHABETS))
    ap.add_argument("--prefix", default="", help="добавить префикс к кандидату")
    args = ap.parse_args()

    if args.unix:
        base = args.unix
    elif args.ts:
        d = dt.datetime.strptime(args.ts, "%Y-%m-%d %H:%M:%S").replace(tzinfo=dt.timezone.utc)
        base = int(d.timestamp())
    else:
        ap.error("нужен --ts или --unix")

    alpha = ALPHABETS[args.alphabet]
    print(f"[+] база: {base} (±{args.range})")
    for i in range(base - args.range, base + args.range + 1):
        random.seed(i)
        key = "".join(random.choice(alpha) for _ in range(args.len))
        print(f"{i}  {args.prefix}{key}")


if __name__ == "__main__":
    main()
