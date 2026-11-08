#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
strings_filter.py — строки из бинарника с фильтрами и смещениями.

  python strings_filter.py bin
  python strings_filter.py bin --grep "flag|pass|key"
  python strings_filter.py bin --flag --url
  python strings_filter.py bin --utf16 --min 6

Ищет ASCII и (опционально) UTF-16LE, печатает offset в hex.
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

ASCII_RE = re.compile(rb"[\x20-\x7e]{4,}")
FLAG_RE = re.compile(rb"[A-Za-z][A-Za-z0-9_]{0,20}\{[\x20-\x7e]{1,200}\}")
URL_RE = re.compile(rb"(?:https?|ftp)://[^\s\"'<>]{4,200}")
PATH_RE = re.compile(rb"(?:[A-Za-z]:\\\\|/(?:etc|home|root|opt|srv|var|usr|tmp)/)[^\s\"'<>]{2,200}")


def utf16_strings(data: bytes, minlen=4):
    out = []
    i = 0
    while i + 1 < len(data):
        # ищем пары "печатный \x00"
        start = None
        chars = []
        j = i
        while j + 1 < len(data):
            c = data[j]
            if 32 <= c < 127 and data[j + 1] == 0:
                if start is None:
                    start = j
                chars.append(chr(c))
                j += 2
            else:
                break
        if start is not None and len(chars) >= minlen:
            out.append((start, "".join(chars)))
            i = j
        else:
            i += 1
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("file")
    ap.add_argument("--min", type=int, default=4)
    ap.add_argument("--utf16", action="store_true")
    ap.add_argument("--grep", help="regex по строке")
    ap.add_argument("--flag", action="store_true")
    ap.add_argument("--url", action="store_true")
    ap.add_argument("--path", action="store_true")
    ap.add_argument("--limit", type=int, default=200)
    args = ap.parse_args()

    data = open(args.file, "rb").read()
    items = [(m.start(), m.group().decode("latin-1")) for m in ASCII_RE.finditer(data)
             if len(m.group()) >= args.min]
    if args.utf16:
        items += [(o, s) for o, s in utf16_strings(data, args.min)]
        items.sort()

    if args.flag:
        flags = sorted({m.group().decode("latin-1") for m in FLAG_RE.finditer(data)})
        for f in flags:
            print(f"[FLAG] {f}")

    shown = 0
    for off, s in items:
        if args.grep and not re.search(args.grep, s, re.I):
            continue
        if args.url and not URL_RE.search(s.encode("latin-1", "ignore")):
            continue
        if args.path and not PATH_RE.search(s.encode("latin-1", "ignore")):
            continue
        if any(x in s for x in ("\x00",)):
            continue
        print(f"0x{off:08x}  {s[:200]}")
        shown += 1
        if shown >= args.limit:
            break
    if not shown:
        print("[-] ничего не найдено; попробуй --utf16 или другой фильтр")


if __name__ == "__main__":
    try:
        main()
    except (FileNotFoundError, IsADirectoryError, PermissionError) as e:
        print(f"[-] не могу открыть: {getattr(e, 'filename', None) or e}")
    except BrokenPipeError:
        pass
    except KeyboardInterrupt:
        print("\n[-] прервано")
