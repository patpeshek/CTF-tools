#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
hash_id.py — определить тип хеша и подсказать режим hashcat.

  python hash_id.py 5f4dcc3b5aa765d61d8327deb882cf99
  python hash_id.py 'sha256:10000:dTh5MERKc0hnVA==:J5LJ...'
  python hash_id.py --file hashes.txt
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

RULES = [
    (r"^[a-f0-9]{32}$", "MD5 / NTLM", "0 (MD5) или 1000 (NTLM)"),
    (r"^[a-f0-9]{40}$", "SHA1", "100"),
    (r"^[a-f0-9]{56}$", "SHA224", "1300"),
    (r"^[a-f0-9]{64}$", "SHA256", "1400"),
    (r"^[a-f0-9]{96}$", "SHA384", "10800"),
    (r"^[a-f0-9]{128}$", "SHA512", "1700"),
    (r"^\$2[aby]\$\d{2}\$", "bcrypt", "3200"),
    (r"^\$6\$", "sha512crypt", "1800"),
    (r"^\$5\$", "sha256crypt", "7400"),
    (r"^\$1\$", "md5crypt", "500"),
    (r"^sha256:\d+:[A-Za-z0-9+/=]+:[A-Za-z0-9+/=]+$",
     "PBKDF2-HMAC-SHA256 (формат Gitea)", "10900, раунды = второе поле"),
    (r"^pbkdf2_sha256\$", "Django PBKDF2-SHA256", "10000"),
    (r"^[A-Za-z0-9+/=]{20,}$", "возможно base64 (не хеш?)", "-"),
]


def identify(h: str):
    h = h.strip()
    for pat, name, mode in RULES:
        if re.match(pat, h):
            return name, mode
    if re.match(r"^[A-Za-z0-9+/=]+$", h) and len(h) % 4 == 0:
        return "base64 (не хеш)", "-"
    return "неизвестно", "-"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("hash", nargs="?")
    ap.add_argument("--file")
    args = ap.parse_args()
    items = []
    if args.file:
        items = [l.strip() for l in open(args.file, encoding="utf-8", errors="replace") if l.strip()]
    elif args.hash:
        items = [args.hash]
    else:
        ap.error("нужен hash или --file")

    for h in items:
        name, mode = identify(h)
        print(f"{h[:70]:72s} -> {name:38s} hashcat: {mode}")


if __name__ == "__main__":
    main()
