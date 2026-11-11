#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
windows_triage.py — быстрый разбор Windows-артефактов без Volatility/regipy.

  python windows_triage.py dump_dir
  python windows_triage.py dump_dir --json

Ищет в текстовых/бинарных артефактах: флаги, URL, пути, автозапуск (Run/RunOnce),
учётки, email, IP, ключи. Работает с SAM/SYSTEM/SOFTWARE/NTUSER.DAT, EVTX, .pf,
.lnk, .xml, .log, .txt — через строки и эвристики.
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

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import common  # noqa: E402

ASCII = re.compile(rb"[\x20-\x7e]{6,}")
URL = re.compile(rb"(?:https?|ftp)://[^\s\"'<>]{4,200}")
WINPATH = re.compile(rb"[A-Za-z]:\\(?:[^\\/:*?\"<>|\r\n]{1,80}\\){0,8}[^\\/:*?\"<>|\r\n]{1,80}")
EMAIL = re.compile(rb"[\w.+-]{2,40}@[\w.-]{2,40}\.[A-Za-z]{2,10}")
IP = re.compile(rb"\b(?:\d{1,3}\.){3}\d{1,3}\b")
RUN = re.compile(rb"(?i)(Run|RunOnce|ImagePath|ServiceDll|UserInit)\b.{0,120}", re.S)
WIDE = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")


def utf16_strings(data: bytes, minlen=4, limit=None):
    """ASCII-строки в UTF-16LE (реестр, EVTX, .lnk хранят текст так)."""
    out = []
    for m in WIDE.finditer(data):
        if len(m.group()) // 2 >= minlen:
            out.append(m.group().decode("utf-16-le"))
            if limit and len(out) >= limit:
                break
    return out


def analyze(path, max_bytes=50_000_000):
    data = open(path, "rb").read(max_bytes)
    info = {"file": path, "size": len(data), "flags": [], "urls": [], "paths": [],
            "run": [], "emails": [], "ips": [], "strings": 0}
    a = [m.group().decode("latin-1") for m in ASCII.finditer(data)]
    u = utf16_strings(data)
    info["strings"] = len(a) + len(u)
    # UTF-16-строки разбираем теми же регулярками, что и сырые байты
    wide = "\n".join(u).encode("latin-1", "replace")
    for src in (data, wide):
        for f in common.find_flags(src):
            if f not in info["flags"]:
                info["flags"].append(f)
    both = (data, wide)
    info["urls"] = sorted({m.group().decode("latin-1") for d in both for m in URL.finditer(d)})[:30]
    info["paths"] = sorted({m.group().decode("latin-1") for d in both for m in WINPATH.finditer(d)})[:30]
    info["emails"] = sorted({m.group().decode("latin-1") for d in both for m in EMAIL.finditer(d)})[:20]
    info["ips"] = sorted({m.group().decode("latin-1") for d in both for m in IP.finditer(d)})[:20]
    info["run"] = [m.group().decode("latin-1", "replace")[:140]
                   for d in both for m in RUN.finditer(d)][:10]
    return info


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("path")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--limit", type=int, default=100,
                    help="сколько файлов проверить (0 = все)")
    common.add_flag_args(ap)
    args = ap.parse_args()
    common.apply_flag_args(args)

    targets = []
    if os.path.isdir(args.path):
        for root, _, files in os.walk(args.path):
            for f in sorted(files):
                targets.append(os.path.join(root, f))
    else:
        targets = [args.path]

    over_limit = max(0, len(targets) - args.limit) if args.limit > 0 else 0
    if over_limit:
        targets = targets[:args.limit]
    too_big = []
    reports = []
    for p in targets:
        try:
            if os.path.getsize(p) > 50_000_000:
                too_big.append(p)
                continue
            info = analyze(p)
        except OSError:
            continue
        reports.append(info)
        interesting = (info["flags"] or info["urls"] or info["run"] or info["paths"])
        if not interesting:
            continue
        print(f"\n=== {p} ({info['size']} b) ===")
        if info["flags"]:
            print("  FLAGS:", " | ".join(info["flags"]))
        if info["urls"]:
            print("  urls:", ", ".join(info["urls"][:5]))
        if info["run"]:
            for x in info["run"][:5]:
                print("  run:", x.replace("\n", " "))
        if info["paths"]:
            print("  paths:", ", ".join(info["paths"][:5]))
        if info["emails"]:
            print("  emails:", ", ".join(info["emails"][:5]))
        if info["ips"]:
            print("  ips:", ", ".join(info["ips"][:5]))

    if over_limit:
        print(f"\n[!] пропущено файлов: {over_limit} (проверено {len(targets)},"
              f" лимит --limit {args.limit}); все: --limit 0")
    if too_big:
        print(f"[!] пропущено больших файлов (>50 MB): {len(too_big)},"
              f" например {too_big[0]}")

    flags = sorted({f for r in reports for f in r["flags"]})
    if flags:
        print("\n=== ФЛАГИ ===")
        for f in flags:
            print(" !!!", f)
    if args.json:
        print(json.dumps(reports, ensure_ascii=False, indent=2, default=str))


if __name__ == "__main__":
    main()
