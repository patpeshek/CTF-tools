#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ipa_info.py — разбор iOS .ipa без Xcode: Payload, Info.plist, строки, флаги.

  python ipa_info.py app.ipa
  python ipa_info.py app.ipa --out extracted
  python ipa_info.py app.ipa --strings 500

IPA — это ZIP: `Payload/<Name>.app/` с `Info.plist` (часто бинарный plist),
исполняемым файлом Mach-O и ресурсами. Скрипт ничего не запускает.
"""
from __future__ import annotations

try:
    import sys as _sys
    for _stream in (_sys.stdout, _sys.stderr):
        _stream.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

import argparse
import os
import plistlib
import re
import sys
import zipfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import common  # noqa: E402


def plist_of(z, name):
    try:
        return plistlib.loads(z.read(name))
    except Exception:
        return {}


def printable_strings(data, min_len=5):
    out = []
    for m in re.finditer(rb"[ -~]{%d,}" % min_len, data):
        try:
            out.append(m.group().decode("ascii"))
        except UnicodeDecodeError:
            continue
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("file")
    ap.add_argument("--out", help="куда распаковать .app")
    ap.add_argument("--strings", type=int, default=300,
                    help="сколько строк показать (0 — не показывать)")
    common.add_flag_args(ap)
    args = ap.parse_args()
    common.apply_flag_args(args)

    if not os.path.isfile(args.file):
        print(f"[-] нет файла: {args.file}")
        return
    try:
        z = zipfile.ZipFile(args.file)
    except zipfile.BadZipFile:
        print("[-] это не ZIP/IPA")
        return

    names = z.namelist()
    print(f"[i] файлов в архиве: {len(names)}")
    apps = sorted({n.split("/")[1] for n in names
                   if n.startswith("Payload/") and n.count("/") >= 1})
    if not apps:
        print("[-] нет Payload/*.app — это не IPA")
        return
    print(f"[i] приложений: {', '.join(apps)}")

    info_name = next((n for n in names if n.endswith(".app/Info.plist")), None)
    info = plist_of(z, info_name) if info_name else {}
    if info:
        print("\n=== Info.plist ===")
        for key in ("CFBundleIdentifier", "CFBundleName", "CFBundleShortVersionString",
                    "CFBundleVersion", "MinimumOSVersion", "CFBundleExecutable"):
            if key in info:
                print(f"  {key}: {info[key]}")
        schemes = []
        for item in info.get("CFBundleURLTypes", []) or []:
            schemes += item.get("CFBundleURLSchemes", []) or []
        if schemes:
            print(f"  URL schemes: {', '.join(map(str, schemes))}")
        ats = info.get("NSAppTransportSecurity")
        if ats:
            print(f"  ATS: {ats}")
        if info.get("NSAllowsArbitraryLoads") or (ats or {}).get("NSAllowsArbitraryLoads"):
            print("  [!] ATS отключён (NSAllowsArbitraryLoads)")

    exe = info.get("CFBundleExecutable") if info else None
    exe_path = next((n for n in names if exe and n.endswith(f".app/{exe}")), None)

    print("\n=== файлы ===")
    for n in names[:40]:
        try:
            size = z.getinfo(n).file_size
        except KeyError:
            size = 0
        print(f"  {size:>9}  {n}")
    if len(names) > 40:
        print(f"  ... ещё {len(names) - 40}")

    if exe_path:
        data = z.read(exe_path)
        print(f"\n=== исполняемый файл ===\n  {exe_path} ({len(data)} байт)")
        strs = printable_strings(data)
        hits = [s for s in strs
                if re.search(r"(?i)flag|ctf\{|https?://|api[_-]?key|secret|token", s)]
        for s in hits[:30]:
            print("   ", s[:200])
        for f in common.find_flags(data):
            print(f"[!!!] ФЛАГ: {f}")

    if args.strings:
        print(f"\n=== строки-кандидаты (до {args.strings}) ===")
        shown = 0
        for n in names:
            if n.endswith("/"):
                continue
            try:
                if z.getinfo(n).file_size > 4_000_000:
                    continue
                data = z.read(n)
            except Exception:
                continue
            for s in printable_strings(data, 6):
                if re.search(r"(?i)flag|ctf\{|https?://|secret|password|api[_-]?key", s):
                    print(f"  [{n}] {s[:180]}")
                    shown += 1
                    if shown >= args.strings:
                        break
            for f in common.find_flags(data):
                print(f"[!!!] ФЛАГ ({n}): {f}")
            if shown >= args.strings:
                break

    if args.out:
        os.makedirs(args.out, exist_ok=True)
        z.extractall(args.out)
        print(f"\n[i] распаковано в {args.out}")


if __name__ == "__main__":
    main()
