#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
py_pack.py — определить упаковщик Python-бинаря и подсказать следующий шаг.

  python py_pack.py app.exe
  python py_pack.py app.pyz
  python py_pack.py app.exe --extract out

Ищет маркеры PyInstaller, pyarmor, Nuitka, py2exe, cx_Freeze, zipapp.
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

MARKERS = [
    (b"MEI\x0c\x0b\x0a\x0b\x0e", "PyInstaller", "CArchive; ищи _MEIPASS и распакуй pyinstxtractor"),
    (b"PYZ-00.pyz", "PyInstaller", "есть PYZ-архив; pyinstxtractor, затем pycdc"),
    (b"pyarmor_runtime", "pyarmor", "обфускация pyarmor: дамп памяти процесса, ищи runtime"),
    (b"pyarmor", "pyarmor", "обфускация pyarmor"),
    (b"Nuitka", "Nuitka", "нативный код; Ghidra/IDA, ищи строки и точки сравнения"),
    (b"py2exe", "py2exe", "распакуй zip-ресурсы, затем pycdc"),
    (b"cx_Freeze", "cx_Freeze", "ищи library.zip и .pyc"),
    (b"__main__.pyc", "zipapp", "это zip; распакуй и декомпилируй .pyc"),
]

INTEREST = re.compile(rb"[ -~]{6,}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("file")
    ap.add_argument("--extract", help="распаковать zip-часть")
    ap.add_argument("--strings", type=int, default=10)
    args = ap.parse_args()

    data = open(args.file, "rb").read()
    print(f"[+] файл: {args.file} ({len(data)} b)")

    hits = []
    for sig, name, advice in MARKERS:
        pos = data.find(sig)
        if pos != -1:
            hits.append((name, pos, advice))

    # zip-внутренности (PyInstaller/zipapp). zipapp может начинаться со строки
    # «#!/usr/bin/env python3», поэтому zip ищется не только в начале файла.
    pk = data.find(b"PK\x03\x04")
    if pk != -1 and (pk == 0 or zipfile.is_zipfile(args.file)):
        try:
            with zipfile.ZipFile(args.file) as z:
                names = z.namelist()
                where = f" после {pk} b префикса" if pk else ""
                if data[:2] == b"#!":
                    where += " (строка #!)"
                print(f"[+] это zip{where}: {len(names)} файлов")
                for n in names[:20]:
                    print("    ", n)
                if ("__main__.py" in names or "__main__.pyc" in names) \
                        and not any(h[0] == "zipapp" for h in hits):
                    hits.append(("zipapp", pk, "python app.pyz; распакуй и смотри __main__.py"))
                if args.extract:
                    os.makedirs(args.extract, exist_ok=True)
                    z.extractall(args.extract)
                    print(f"[+] распаковано: {args.extract}")
        except zipfile.BadZipFile:
            print("[!] PK-сигнатура есть, но zip не открылся (может быть CArchive)")

    if not hits:
        print("[-] известных маркеров не найдено")
    for name, pos, advice in hits:
        print(f"[+] {name} @ 0x{pos:x}: {advice}")

    # интересные строки
    ss = [m.group().decode("latin-1") for m in INTEREST.finditer(data)]
    keys = [s for s in ss if any(w in s.lower() for w in ("key", "secret", "password", "flag", "license"))]
    if keys:
        print("[+] подозрительные строки:")
        for s in keys[:args.strings]:
            print("    ", s[:160])


if __name__ == "__main__":
    try:
        main()
    except (FileNotFoundError, IsADirectoryError, PermissionError) as e:
        print(f"[-] не могу открыть: {getattr(e, 'filename', None) or e}")
    except BrokenPipeError:
        pass
    except KeyboardInterrupt:
        print("\n[-] прервано")
