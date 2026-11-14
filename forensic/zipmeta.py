#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
zipmeta.py — комментарии, extra-поля и имена ZIP.

  python zipmeta.py archive.zip
  python zipmeta.py archive.zip --decode

С флагом --decode имена читаются как байты: hex-имя целиком, а также
«флаг, разрезанный по индексам» (`00_66.dat`, `01_6c.dat`, … — в имени
номер записи и hex одного байта). Комментарии и extra-поля тоже пробуются
как hex/base64/reverse.
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
import os
import re
import sys
import zipfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import common  # noqa: E402

# имя = номер записи + hex байта(ов), опционально расширение: 00_66.dat
SPLIT_RE = re.compile(r"^(\d+)[_\-.]((?:[0-9a-fA-F]{2})+)(?:\.[A-Za-z0-9]{1,8})?$")
# имя целиком — hex: 666c6167
HEXNAME_RE = re.compile(r"^((?:[0-9a-fA-F]{2}){2,})$")


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


def decode_names(names):
    """[(как_прочитали, байты)] из имён записей.

    Два способа спрятать флаг в именах:
      * имя целиком hex (`666c6167.dat` → `flag`);
      * флаг разрезан на записи, в имени номер и hex одного байта
        (`00_66.dat`, `01_6c.dat`, …) — собираем по номеру.
    """
    out = []
    parts = []
    for name in names:
        base = name.rsplit("/", 1)[-1]
        m = SPLIT_RE.match(base)
        if m:
            parts.append((int(m.group(1)), bytes.fromhex(m.group(2))))
            continue
        m = HEXNAME_RE.match(base)
        if m:
            out.append((f"hex-имя {base}", bytes.fromhex(m.group(1))))
    if len(parts) >= 2:
        parts.sort(key=lambda p: p[0])
        out.append((f"имена по индексу ({len(parts)} записей)",
                    b"".join(b for _, b in parts)))
    elif parts:
        out.append(("hex-имя", parts[0][1]))
    return out


def show(where, blob):
    """Напечатать расшифрованный кусок и найденные в нём флаги."""
    if not blob:
        return
    txt = "".join(chr(c) if 32 <= c < 127 else "." for c in blob[:200])
    print(f"    {where}: {txt}")
    for fl in common.find_flags(blob):
        print(f"[FLAG] {fl}   ({where})")


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
        if args.decode:
            # имена — такой же носитель, как комментарий: hex/разрез по индексам
            for how, blob in decode_names([i.filename for i in z.infolist()]):
                show(how, blob)
            for i in z.infolist():
                if i.extra:
                    for how, d in variants(i.extra):
                        show(f"extra {i.filename} ({how})", d)
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
