#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
apk_info.py — разбор APK: файлы, manifest, строки, ссылки, флаги.

  python apk_info.py app.apk
  python apk_info.py app.apk --strings 40
  python apk_info.py app.apk --extract out

APK — это zip. AndroidManifest.xml внутри бинарный (AXML), поэтому строки
достаются эвристикой: UTF-16LE и ASCII.
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
import sys
import zipfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import common

ASCII = re.compile(rb"[\x20-\x7e]{6,}")
UTF16 = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")
URL = re.compile(rb"(?:https?|ftp)://[^\s\"'<>]{4,200}")

INTEREST = ("password", "secret", "token", "api", "key", "firebase", "http")
MAX_READ = 64 * 1024 * 1024


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("apk")
    ap.add_argument("--strings", type=int, default=20)
    ap.add_argument("--extract")
    common.add_flag_args(ap)
    args = ap.parse_args()
    common.apply_flag_args(args)

    with zipfile.ZipFile(args.apk) as z:
        infos = z.infolist()
        print(f"[+] файлов: {len(infos)}")
        groups = {}
        for i in infos:
            top = i.filename.split("/")[0]
            groups.setdefault(top, [0, 0])
            groups[top][0] += 1
            groups[top][1] += i.file_size
        for g, (cnt, size) in sorted(groups.items(), key=lambda x: -x[1][1]):
            print(f"    {g:20s} {cnt:5d} файлов  {size/1024:.0f} KB")

        # manifest
        if "AndroidManifest.xml" in z.namelist():
            raw = z.read("AndroidManifest.xml")
            print("\n[+] AndroidManifest.xml:")
            if raw[:2] == b"\x03\x00" or b"\x00" in raw[:8]:
                strings = []
                for m in UTF16.finditer(raw):
                    try:
                        strings.append(m.group().decode("utf-16le"))
                    except UnicodeDecodeError:
                        pass
            else:
                strings = [m.group().decode("latin-1") for m in ASCII.finditer(raw)]
            uniq = list(dict.fromkeys(strings))
            for s in uniq[:args.strings]:
                print("    ", s[:160])
            perms = [s for s in uniq if "permission" in s.lower()]
            if perms:
                print("    permissions:")
                for p in perms[:20]:
                    print("      ", p)

        # dex, resources.arsc, assets/, res/raw/ и прочие — интересные строки
        found_flags = set()
        urls = set()
        keys = []
        too_big = []
        for i in infos:
            low = i.filename.lower()
            if not (low.endswith((".dex", ".xml", ".json", ".properties", ".so", ".arsc"))
                    or low.startswith(("assets/", "res/raw/"))):
                continue
            if i.file_size > MAX_READ:
                too_big.append(i.filename)
                continue
            try:
                data = z.read(i)
            except Exception:
                continue
            # пул строк resources.arsc и бинарный XML часто в UTF-16LE: флаги
            # ищем везде, URL/ключи — только в arsc/assets (в AXML-разметке
            # это сплошь schemas.android.com)
            wide = b"\n".join(m.group().decode("utf-16-le").encode("ascii")
                              for m in UTF16.finditer(data))
            for f in common.find_flags(wide):
                found_flags.add(f)
            rich = low.endswith(".arsc") or low.startswith(("assets/", "res/raw/"))
            for blob in ((data, wide) if rich else (data,)):
                for f in common.find_flags(blob):
                    found_flags.add(f)
                for m in URL.finditer(blob):
                    urls.add(m.group().decode("latin-1"))
                for m in ASCII.finditer(blob):
                    s = m.group().decode("latin-1")
                    if any(w in s.lower() for w in INTEREST):
                        keys.append((i.filename, s))
        if too_big:
            print(f"\n[!] пропущено больших файлов (>{MAX_READ >> 20} MB): {len(too_big)},"
                  f" например {too_big[0]}")

        if found_flags:
            print("\n[!!!] флаги:", " | ".join(sorted(found_flags)))
        if urls:
            print("\n[+] URL (первые 15):")
            for u in sorted(urls)[:15]:
                print("    ", u)
        if keys:
            print("\n[+] подозрительные строки:")
            for f, s in keys[:args.strings]:
                print(f"    {f}: {s[:140]}")

        if args.extract:
            os.makedirs(args.extract, exist_ok=True)
            z.extractall(args.extract)
            print(f"\n[+] распаковано: {args.extract}")


if __name__ == "__main__":
    try:
        main()
    except (FileNotFoundError, IsADirectoryError, PermissionError) as e:
        print(f"[-] не могу открыть: {getattr(e, 'filename', None) or e}")
    except BrokenPipeError:
        pass
    except KeyboardInterrupt:
        print("\n[-] прервано")
