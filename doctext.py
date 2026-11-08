#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
doctext.py — вытащить текст из документа/архива, чтобы гонять по нему инструменты.

  python doctext.py document.docx
  python doctext.py document.docx --out document.txt
  python doctext.py document.pdf --classify
  python doctext.py archive.zip --out dump.txt

Поддержано: DOCX/XLSX/PPTX (zip + XML), PDF (pypdf), обычный текст.
Для DOCX/PDF пробелы, табы и zero-width сохраняются — дальше их можно кормить
в whitespace.py / esolang.py / enc.py.
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
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import common  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("file")
    ap.add_argument("--out")
    ap.add_argument("--classify", action="store_true")
    ap.add_argument("--limit", type=int, default=2000, help="сколько символов печатать")
    common.add_flag_args(ap)
    args = ap.parse_args()
    common.apply_flag_args(args)

    segs = common.document_text(args.file)
    if not segs:
        print("[-] не нашёл текста (может быть картинка/бинарник — используй triage)")
        return

    parts = []
    for label, text in segs:
        print(f"\n=== {label} ({len(text)} символов) ===")
        if args.classify:
            tags = common.classify_text(text)
            print("теги:", ", ".join(tags) if tags else "нет")
        print(text[:args.limit])
        if text:
            parts.append(text)

    if args.out:
        open(args.out, "w", encoding="utf-8").write("\n".join(parts))
        print(f"\n[+] сохранено: {args.out}")
        print("[i] дальше: python toolbox.py ws/enc/esolang/obscure " + args.out)


if __name__ == "__main__":
    main()
