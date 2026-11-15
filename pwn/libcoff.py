#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
libcoff.py — смещения libc для ret2libc: system, execve, /bin/sh, версия.

  python libcoff.py libc.so.6
  python libcoff.py libc.so.6 --base 0x7ffff7dc0000
  python libcoff.py libc.so.6 --json

Зачем: в ret2libc-задаче 80% работы — узнать смещения `system` и строки
`/bin/sh` в конкретной libc. Если рядом с бинарником лежит libc.so.6, это
считается здесь без запуска эксплойта и без pwntools.

Смещение = адрес в файле (st_value), он же смещение от базы libc.
"""
from __future__ import annotations

try:
    import sys as _sys
    for _stream in (_sys.stdout, _sys.stderr):
        _stream.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

import argparse
import importlib.util
import json
import os
import re
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location(
    "elf_symbols", os.path.join(_HERE, "..", "reverse", "symbols.py"))
elf_symbols = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(elf_symbols)          # type: ignore[union-attr]

WANTED = ("system", "execve", "puts", "printf", "read", "write", "mprotect",
          "__libc_system", "str_bin_sh")


def find_string_addr(data: bytes, needle: bytes):
    """Виртуальный адрес строки в ELF (для /bin/sh)."""
    idx = data.find(needle)
    if idx < 0:
        return None
    for _nm, _t, a, o, sz, _l, _e in elf_symbols._sections(data):
        if o <= idx < o + sz:
            return a + (idx - o)
    return idx


def analyse(path: str, base: int | None = None):
    with open(path, "rb") as fh:
        data = fh.read(128 * 1024 * 1024)
    syms, note = elf_symbols.symbols(data)
    out = {"file": path, "note": note, "version": None, "offsets": {}}
    m = re.search(rb"GNU C Library[^\x00]{0,120}", data)
    if m:
        out["version"] = m.group(0).decode("latin-1", "replace").strip()
    else:
        m = re.search(rb"glibc[ -]?2\.\d+[^\x00]{0,20}", data)
        out["version"] = m.group(0).decode("latin-1", "replace") if m else None

    seen = set()
    for name, value, typ in syms:
        clean = name.lstrip("_") if name.startswith("__libc_") else name
        if clean in WANTED and clean not in seen and value:
            seen.add(clean)
            key = "system" if name in ("__libc_system", "system") else clean
            if key in out["offsets"]:
                continue
            out["offsets"][key] = value

    binsh = find_string_addr(data, b"/bin/sh\x00")
    if binsh is not None:
        out["offsets"]["binsh"] = binsh

    if base is not None:
        out["absolute"] = {k: hex(base + v) for k, v in out["offsets"].items()}
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("file")
    ap.add_argument("--base", default=None,
                    help="база libc (hex) — печатает абсолютные адреса")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    base = int(args.base, 16) if args.base else None
    try:
        r = analyse(args.file, base)
    except OSError as exc:
        print(f"[-] {exc}")
        return 2
    if args.json:
        print(json.dumps(r, ensure_ascii=False))
        return 0
    print(f"[+] {args.file}")
    if r["version"]:
        print(f"    версия: {r['version']}")
    if r["note"]:
        print(f"    {r['note']}")
    if not r["offsets"]:
        print("[-] не нашёл ни system, ни /bin/sh (не libc?)")
        return 1
    for name in ("system", "execve", "puts", "printf", "read", "write",
                 "mprotect", "binsh"):
        if name in r["offsets"]:
            v = r["offsets"][name]
            line = f"    {name:9s} offset {v:#x}"
            if base is not None:
                line += f"   → {v + base:#x}"
            print(line)
    if "binsh" not in r["offsets"]:
        print("    [!] /bin/sh не найден — ищи строку вручную")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
