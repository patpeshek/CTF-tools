#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ooxml.py — DOCX/XLSX/PPTX как ZIP: распаковать, показать media, прогнать strings.

  python ooxml.py zagadka.docx
  python ooxml.py zagadka.docx --extract out --strings
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
import os
import re
import zipfile

PRINTABLE = re.compile(rb"[\x20-\x7e]{6,}")
FLAG = re.compile(rb"(?:CTF|ctf|flag)\{[^}]{1,200}\}")
TEXT_PART = re.compile(r"\.(?:xml|rels|vml|txt|html?|csv|json)$", re.I)
USTR = re.compile(r"[^\x00-\x1f\x7f-\x9f�]{6,}")


def part_strings(name, data):
    """strings одной части: XML — UTF-8, по тегу на строку (видно текст,
    атрибуты, комментарии); бинарные части — ASCII strings."""
    if TEXT_PART.search(name) or data.lstrip()[:5] == b"<?xml":
        text = re.sub(r">\s*<", ">\n<", data.decode("utf-8", "replace"))
        return [s.strip() for s in USTR.findall(text) if len(s.strip()) >= 6]
    return [s.decode("ascii") for s in PRINTABLE.findall(data)]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("file")
    ap.add_argument("--extract", help="куда распаковать")
    ap.add_argument("--strings", action="store_true",
                    help="печатать strings из всех частей (без --strings — "
                         "первые 10 из media)")
    args = ap.parse_args()

    with zipfile.ZipFile(args.file) as z:
        infos = z.infolist()
        print(f"[+] файлов внутри: {len(infos)}")
        for i in infos:
            extra = f"  COMMENT={i.comment!r}" if i.comment else ""
            print(f"  - {i.filename:45s} {i.file_size:>8} b{extra}")

        if args.extract:
            os.makedirs(args.extract, exist_ok=True)
            z.extractall(args.extract)
            print(f"[+] распаковано в: {args.extract}")

        media = [i for i in infos if i.filename.startswith(("word/media", "xl/media", "ppt/media"))]
        print(f"[+] media: {[m.filename for m in media]}")

        for m in media:
            data = z.read(m)
            flags = FLAG.findall(data)
            if flags:
                print(f"[!!!] флаг в {m.filename}: {flags}")
            if not args.strings:   # краткий обзор; полный — ниже по --strings
                ss = [s.decode("utf-8", "replace") for s in PRINTABLE.findall(data)][:10]
                if ss:
                    print(f"[+] strings {m.filename}:")
                    for s in ss:
                        print("     ", s[:120])

        if args.strings:
            for i in infos:
                if i.is_dir():
                    continue
                ss = part_strings(i.filename, z.read(i))
                if ss:
                    print(f"[+] strings {i.filename} ({len(ss)}):")
                    for s in ss:
                        print("     ", s)


if __name__ == "__main__":
    try:
        main()
    except (FileNotFoundError, IsADirectoryError, PermissionError) as e:
        print(f"[-] не могу открыть: {getattr(e, 'filename', None) or e}")
    except BrokenPipeError:
        pass
    except KeyboardInterrupt:
        print("\n[-] прервано")
