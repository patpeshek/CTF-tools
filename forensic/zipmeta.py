#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
zipmeta.py — комментарии и extra-поля ZIP.

  python zipmeta.py archive.zip
  python zipmeta.py archive.zip --decode
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
import binascii
import zipfile


def variants(raw: bytes):
    """Пробуем прочитать комментарий как hex / base64 / перевёрнутую строку."""
    out = []
    for name, fn in (
        ("hex", lambda b: binascii.unhexlify(b.strip())),
        ("base64", lambda b: base64.b64decode(b.strip() + b"=" * (-len(b.strip()) % 4))),
    ):
        try:
            d = fn(raw)
            if d:
                out.append((name, d))
        except Exception:
            pass
    try:
        rev = raw[::-1]
        out.append(("reverse", rev))
    except Exception:
        pass
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("file")
    ap.add_argument("--decode", action="store_true", help="пробовать hex/base64/reverse")
    args = ap.parse_args()

    with zipfile.ZipFile(args.file) as z:
        if z.comment:
            print(f"[+] комментарий архива: {z.comment!r}")
            if args.decode:
                for how, d in variants(z.comment):
                    print(f"    {how}: {d[:200]!r}")
        for i in z.infolist():
            if i.comment:
                print(f"[+] комментарий файла {i.filename}: {i.comment!r}")
                if args.decode:
                    for how, d in variants(i.comment):
                        print(f"    {how}: {d[:200]!r}")
            if i.extra:
                print(f"[+] extra {i.filename}: {i.extra.hex()}")
        if not z.comment and not any(i.comment for i in z.infolist()):
            print("[-] комментариев нет. Смотри имена файлов, даты, extra-поля.")
        print(f"[+] файлов: {len(z.infolist())}")
        for i in z.infolist():
            print(f"    {i.filename:45s} {i.file_size:>8} b  date={i.date_time}")


if __name__ == "__main__":
    try:
        main()
    except (FileNotFoundError, IsADirectoryError, PermissionError) as e:
        print(f"[-] не могу открыть: {getattr(e, 'filename', None) or e}")
    except BrokenPipeError:
        pass
    except KeyboardInterrupt:
        print("\n[-] прервано")
