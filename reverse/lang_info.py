#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
lang_info.py — определить язык/платформу бинарника и что с ним делать.

  python lang_info.py app.exe
  python lang_info.py app.jar
  python lang_info.py ./bin --json

Поддержано: .NET, Java/JAR, Android DEX/APK, Go, Rust, Electron, Python
(PyInstaller/pyarmor), Mach-O, PE, ELF.
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
import json
import os
import re
import sys
import zipfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import common  # noqa: E402


def analyse(path):
    data = open(path, "rb").read(50_000_000)
    info = {"file": path, "size": len(data), "kind": common.sniff(data),
            "language": None, "notes": [], "version": None, "entries": []}

    if data[:4] in (b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe",
                    b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe"):
        info["language"] = "Mach-O"
        info["notes"].append("Ghidra/IDA, Hopper")

    if b"BSJB" in data or b"mscoree" in data or b"_CorExeMain" in data:
        info["language"] = ".NET"
        info["notes"].append("dnSpy / ILSpy / dotPeek")
        m = re.search(rb"v[0-9]\.[0-9]\.[0-9]{4}", data)
        if m:
            info["version"] = m.group().decode()

    if zipfile.is_zipfile(path):
        try:
            with zipfile.ZipFile(path) as z:
                names = z.namelist()
                info["entries"] = names[:30]
                if any(n.endswith(".class") for n in names):
                    info["language"] = "Java/JAR"
                    info["notes"].append("jadx / CFR / procyon")
                    info["entries"] = [n for n in names if n.endswith(".class")][:30]
                if "classes.dex" in names:
                    info["language"] = "Android/Java"
                    info["notes"].append("jadx / apktool")
                    info["entries"] = [n for n in names if n.endswith(".dex")][:10]
                if "app.asar" in names or any("Electron" in n for n in names):
                    info["language"] = "Electron"
                    info["notes"].append("asar extract app.asar")
        except Exception:
            pass

    if b".go.buildinfo" in data or b"go1." in data:
        info["language"] = "Go"
        m = re.search(rb"go1\.[0-9]+(?:\.[0-9]+)?", data)
        if m:
            info["version"] = m.group().decode()
        m = re.search(rb"path\t([^\x00\n]{2,120})", data)
        if m:
            info["notes"].append("module: " + m.group(1).decode("latin-1", "replace"))
        info["notes"].append("GoReSym, затем Ghidra/IDA")

    if b"rustc" in data or b"cargo" in data:
        info["language"] = info["language"] or "Rust"
        info["notes"].append("Ghidra; ищи строки и сравнения")

    if b"MEI\x0c\x0b\x0a\x0b\x0e" in data or b"PYZ-00.pyz" in data:
        info["language"] = "Python/PyInstaller"
        info["notes"].append("pyinstxtractor, затем pycdc")
    if b"pyarmor_runtime" in data:
        info["language"] = "Python/pyarmor"
        info["notes"].append("дамп памяти, ищи pyarmor_runtime")
    if b"Nuitka" in data:
        info["language"] = "Python/Nuitka"
        info["notes"].append("Ghidra/IDA")

    if info["language"] is None:
        if data[:2] == b"MZ":
            info["language"] = "PE (native)"
            info["notes"].append("Ghidra/IDA, strings")
        elif data[:4] == b"\x7fELF":
            info["language"] = "ELF (native)"
            info["notes"].append("Ghidra/IDA, checksec")
    return info


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("file")
    ap.add_argument("--json", action="store_true")
    common.add_flag_args(ap)
    args = ap.parse_args()
    common.apply_flag_args(args)

    info = analyse(args.file)
    if args.json:
        print(json.dumps(info, ensure_ascii=False, indent=2))
        return
    print(f"[+] {args.file} ({info['size']} b)")
    print(f"    kind:     {info['kind']}")
    print(f"    language: {info['language'] or 'неизвестно'}")
    if info["version"]:
        print(f"    version:  {info['version']}")
    for n in info["notes"]:
        print("    ->", n)
    if info["entries"]:
        print("    entries:")
        for e in info["entries"][:15]:
            print("      ", e)


if __name__ == "__main__":
    try:
        main()
    except (FileNotFoundError, IsADirectoryError, PermissionError) as e:
        print(f"[-] не могу открыть: {getattr(e, 'filename', None) or e}")
    except BrokenPipeError:
        pass
    except KeyboardInterrupt:
        print("\n[-] прервано")
