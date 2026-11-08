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


def utf16_strings(data: bytes, minlen=4, limit=200):
    out = []
    i = 0
    while i + 1 < len(data):
        start = None
        chars = []
        j = i
        while j + 1 < len(data):
            c = data[j]
            if 32 <= c < 127 and data[j + 1] == 0:
                if start is None:
                    start = j
                chars.append(chr(c))
                j += 2
            else:
                break
        if start is not None and len(chars) >= minlen:
            out.append("".join(chars))
            i = j
            if len(out) >= limit:
                break
        else:
            i += 1
    return out


def analyze(path, max_bytes=50_000_000):
    data = open(path, "rb").read(max_bytes)
    info = {"file": path, "size": len(data), "flags": [], "urls": [], "paths": [],
            "run": [], "emails": [], "ips": [], "strings": 0}
    for f in common.find_flags(data):
        info["flags"].append(f)
    info["urls"] = sorted({m.group().decode("latin-1") for m in URL.finditer(data)})[:30]
    info["paths"] = sorted({m.group().decode("latin-1") for m in WINPATH.finditer(data)})[:30]
    info["emails"] = sorted({m.group().decode("latin-1") for m in EMAIL.finditer(data)})[:20]
    info["ips"] = sorted({m.group().decode("latin-1") for m in IP.finditer(data)})[:20]
    info["run"] = [m.group().decode("latin-1", "replace")[:140] for m in RUN.finditer(data)][:10]
    a = [m.group().decode("latin-1") for m in ASCII.finditer(data)]
    u = utf16_strings(data)
    info["strings"] = len(a) + len(u)
    if not (info["urls"] or info["paths"] or info["run"] or info["flags"]):
        info["strings"] = info["strings"]  # уже посчитано
    return info


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("path")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--limit", type=int, default=100)
    common.add_flag_args(ap)
    args = ap.parse_args()
    common.apply_flag_args(args)

    targets = []
    if os.path.isdir(args.path):
        for root, _, files in os.walk(args.path):
            for f in files[:args.limit]:
                targets.append(os.path.join(root, f))
    else:
        targets = [args.path]

    reports = []
    for p in targets[:args.limit]:
        try:
            if os.path.getsize(p) > 50_000_000:
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

    flags = sorted({f for r in reports for f in r["flags"]})
    if flags:
        print("\n=== ФЛАГИ ===")
        for f in flags:
            print(" !!!", f)
    if args.json:
        print(json.dumps(reports, ensure_ascii=False, indent=2, default=str))


if __name__ == "__main__":
    main()
