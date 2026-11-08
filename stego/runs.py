#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
runs.py — серии одинаковых символов как ASCII.

  python runs.py brackets.txt
  python runs.py brackets.txt --chars "<>{}[]()"
  python runs.py brackets.txt --reverse
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


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("file")
    ap.add_argument("--chars", default="", help="учитывать только эти символы (по умолчанию все)")
    ap.add_argument("--reverse", action="store_true", help="перевернуть результат")
    args = ap.parse_args()

    text = open(args.file, "r", encoding="utf-8", errors="replace").read()
    allowed = set(args.chars) if args.chars else None

    out = []
    prev = None
    run = 0

    def flush(ch, n):
        if n and 1 <= n <= 0x10FFFF:
            out.append((n, ch))

    for ch in text:
        if allowed is not None and ch not in allowed:
            flush(prev, run)
            prev, run = None, 0
            continue
        if ch == prev:
            run += 1
        else:
            flush(prev, run)
            prev, run = ch, 1
    flush(prev, run)

    nums = [n for n, _ in out]
    s = "".join(chr(n) if 32 <= n < 127 else "." for n in nums)
    if args.reverse:
        s = s[::-1]
    print("[+] длины серий:", nums[:200])
    print("[+] текст:")
    print(s[:1000])
    cut = s.find("}")
    if cut != -1:
        print("\n[+] до '}':", s[:cut + 1])


if __name__ == "__main__":
    try:
        main()
    except (FileNotFoundError, IsADirectoryError, PermissionError) as e:
        print(f"[-] не могу открыть: {getattr(e, 'filename', None) or e}")
    except BrokenPipeError:
        pass
    except KeyboardInterrupt:
        print("\n[-] прервано")
