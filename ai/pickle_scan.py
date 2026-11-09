#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""pickle_scan.py — статический разбор pickle/моделей: опасные глобалы и строки.

  python pickle_scan.py model.pkl
  python pickle_scan.py model.pt --all
  python pickle_scan.py dump/ --all

Ничего не загружает и не выполняет: только `pickletools.genops`. Ищет
`os.system`, `subprocess.*`, `builtins.eval/exec`, `socket`, `ctypes` и т.п.,
плюс строки/байты и флаги внутри.
"""
from __future__ import annotations

try:
    import sys as _sys
    for _stream in (_sys.stdout, _sys.stderr):
        _stream.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

import argparse
import io
import os
import pickletools
import re
import sys
import zipfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import common  # noqa: E402

DANGEROUS = (
    "os.system", "os.popen", "os.exec", "os.spawn", "os.fork",
    "subprocess.", "commands.", "pty.", "posix.", "nt.",
    "builtins.eval", "builtins.exec", "builtins.compile", "builtins.__import__",
    "__builtin__.eval", "__builtin__.exec", "__builtin__.__import__",
    "eval", "exec", "compile", "socket.", "ctypes.", "shutil.", "runpy.",
    "importlib.", "pickle.loads", "marshal.loads", "codecs.decode",
)


def _ops_from(data: bytes, start: int):
    ops = []
    try:
        for opcode, arg, pos in pickletools.genops(io.BytesIO(data[start:])):
            ops.append((opcode, arg, pos + start))
    except Exception:
        pass
    return ops


def _best_ops(data: bytes):
    """pickle может лежать не с нуля (префикс, склейка) — ищем лучший старт."""
    candidates = [0]
    candidates += [i for i, b in enumerate(data[:1_000_000]) if b == 0x80][:8]
    candidates += [i for i, b in enumerate(data[:1_000_000]) if b == ord("c")][:8]
    best = []
    for start in candidates:
        ops = _ops_from(data, start)
        if len(ops) > len(best):
            best = ops
    return best


def scan_blob(data: bytes, label: str, strings_limit=40):
    print(f"\n=== {label} ({len(data)} байт) ===")
    dangerous, strings = [], []
    ops = _best_ops(data)
    for opcode, arg, pos in ops:
        name = opcode.name
        if name in ("GLOBAL", "STACK_GLOBAL", "INST", "OBJ", "REDUCE"):
            text = str(arg) if arg is not None else name
            low = text.lower()
            if any(d in low for d in DANGEROUS):
                dangerous.append((pos, name, text))
        if name in ("SHORT_BINSTRING", "BINSTRING", "BINUNICODE", "UNICODE",
                    "SHORT_BINUNICODE", "BINBYTES", "SHORT_BINBYTES", "STRING"):
            if isinstance(arg, bytes):
                try:
                    text = arg.decode("utf-8", "replace")
                except Exception:
                    text = repr(arg[:80])
            else:
                text = str(arg)
            if text:
                strings.append(text)

    if not ops:
        print("[!] pickle-опкоды не разобрались — смотрю текст")
        text = data.decode("latin-1", "replace").lower()
        for name in ("os.system", "subprocess", "builtins.eval", "eval(",
                     "exec(", "socket.", "ctypes.", "pickle.loads"):
            if name in text:
                dangerous.append((-1, "text", name))
    elif dangerous:
        print(f"[!] опасные глобалы: {len(dangerous)}")
        for pos, op, text in dangerous[:30]:
            print(f"    offset {pos:>7}  {op:12s} {text[:120]}")
    else:
        print("[+] опасных глоболов не видно")

    interesting = [s for s in strings
                   if re.search(r"(?i)flag|ctf\{|http|token|secret|password|key", s)]
    for s in (interesting or strings)[:strings_limit]:
        print(f"    str: {s[:180]}")

    for f in common.find_flags(data):
        print(f"[!!!] ФЛАГ: {f}")
    for s in strings:
        for f in common.find_flags(s.encode("utf-8", "replace")):
            print(f"[!!!] ФЛАГ (строка): {f}")


def looks_like_pickle(data: bytes) -> bool:
    return data[:1] == b"\x80" or data[:2] in (b"c(", b"c]", b"(l", b"(d")


def scan_file(path):
    try:
        data = open(path, "rb").read(64 * 1024 * 1024)
    except OSError as e:
        print(f"[-] {path}: {e}")
        return
    if zipfile.is_zipfile(io.BytesIO(data)):
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                print(f"[i] {path}: ZIP-контейнер, файлов {len(z.namelist())}")
                for name in z.namelist():
                    if name.endswith("/"):
                        continue
                    chunk = z.read(name)
                    if looks_like_pickle(chunk) or name.endswith((".pkl", ".pickle")):
                        scan_blob(chunk, f"{os.path.basename(path)}::{name}")
        except Exception as e:
            print(f"[!] {path}: не разобрать ZIP: {e}")
        return
    scan_blob(data, os.path.basename(path))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("target")
    ap.add_argument("--all", action="store_true", help="обойти папку рекурсивно")
    common.add_flag_args(ap)
    args = ap.parse_args()
    common.apply_flag_args(args)

    if os.path.isfile(args.target):
        scan_file(args.target)
        return
    if not os.path.isdir(args.target):
        print(f"[-] нет файла/папки: {args.target}")
        return
    exts = (".pkl", ".pickle", ".pt", ".pth", ".joblib", ".bin", ".model")
    found = 0
    for dp, dn, fn in os.walk(args.target):
        for name in fn:
            path = os.path.join(dp, name)
            if args.all or name.lower().endswith(exts):
                try:
                    head = open(path, "rb").read(2)
                except OSError:
                    continue
                if args.all and not (looks_like_pickle(head) or
                                     name.lower().endswith(exts)):
                    continue
                scan_file(path)
                found += 1
    if not found:
        print("[-] pickle-файлов не найдено")


if __name__ == "__main__":
    main()
