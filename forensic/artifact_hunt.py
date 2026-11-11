#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
artifact_hunt.py — рекурсивный поиск артефактов в файлах и архивах.

Ищет: флаги, KEY=VALUE, секреты/пароли/seed/nonce/android_id/machine_id,
base64 и длинные hex-строки. Умеет заглядывать внутрь zip.

  python artifact_hunt.py dump_dir
  python artifact_hunt.py dump_dir --zip --max-size 20
  python artifact_hunt.py app-log.txt --context 1
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
import bisect
import os
import re
import sys
import zipfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import common

PATTERNS = [
    # [ \t]*, а не \s*: `^\s*` в (?m) на файле из переводов строк — O(n^2)
    ("KV", re.compile(r"(?m)^[ \t]*[A-Z][A-Z0-9_]{2,40}[ \t]*=[ \t]*\S+")),
    ("SECRET", re.compile(r"(?i)\b(key|secret|token|password|passwd|seed|nonce|android_id|"
                          r"machine_id|slot|salt|iv)\b\s*[:=]\s*['\"]?([^\s'\"<>]{4,120})")),
    ("B64", re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")),
    ("HEX", re.compile(r"\b[0-9a-fA-F]{32,}\b")),
]


HITS = []


def scan_text(name, text, args):
    # номер строки — бинпоиском по позициям \n (count() на каждое совпадение
    # давал O(n * hits))
    nl = [m.start() for m in re.finditer("\n", text)]
    ctx = max(0, getattr(args, "context", 0) or 0)
    lines = text.split("\n") if ctx else []

    def add(tag, pos, snippet):
        line_no = bisect.bisect_left(nl, pos) + 1
        hit = {"file": name, "line": line_no, "tag": tag, "snippet": snippet}
        if ctx:
            lo = max(0, line_no - 1 - ctx)
            hit["context"] = [(lo + i + 1, s.rstrip("\r")[:300])
                              for i, s in enumerate(lines[lo:line_no + ctx])]
        HITS.append(hit)

    for tag, rx in PATTERNS:
        for m in rx.finditer(text):
            start = max(0, m.start() - 40)
            end = min(len(text), m.end() + 40)
            add(tag, m.start(), text[start:end].replace("\n", " ")[:220])
    for flag in common.find_flags(text.encode("utf-8", "replace")):
        pos = text.find(flag)
        add("FLAG", pos if pos >= 0 else 0, flag)


def scan_file(path, args):
    try:
        size = os.path.getsize(path)
    except OSError:
        return
    if size > args.max_size * 1024 * 1024:
        return
    with open(path, "rb") as f:
        data = f.read()
    text = data.decode("utf-8", "replace")
    if "\x00" in text[:2000] and not args.force:
        return
    scan_text(path, text, args)


def scan_zip(path, args):
    try:
        with zipfile.ZipFile(path) as z:
            for info in z.infolist():
                if info.file_size > args.max_size * 1024 * 1024:
                    continue
                try:
                    data = z.read(info)
                except Exception:
                    continue
                text = data.decode("utf-8", "replace")
                scan_text(f"{path}!{info.filename}", text, args)
    except zipfile.BadZipFile:
        pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("path")
    ap.add_argument("--zip", action="store_true", help="заглядывать в zip")
    ap.add_argument("--max-size", type=int, default=10, help="МБ на файл")
    ap.add_argument("--context", type=int, default=0,
                    help="сколько строк до/после находки печатать")
    ap.add_argument("--force", action="store_true", help="сканировать и бинарники")
    ap.add_argument("--json", action="store_true")
    common.add_flag_args(ap)
    args = ap.parse_args()
    common.apply_flag_args(args)

    targets = []
    if os.path.isdir(args.path):
        for root, _, files in os.walk(args.path):
            for f in files:
                targets.append(os.path.join(root, f))
    else:
        targets = [args.path]

    for p in targets:
        scan_file(p, args)
        if args.zip and p.lower().endswith(".zip"):
            scan_zip(p, args)

    if args.json:
        import json as _json
        print(_json.dumps(HITS, ensure_ascii=False, indent=2))
    else:
        seen = set()
        for h in HITS:
            key = (h["tag"], h["snippet"])
            if key in seen:
                continue
            seen.add(key)
            print(f"{h['file']}:{h['line']} [{h['tag']}] {h['snippet']}")
            for n, s in h.get("context", []):
                print(f"    {n:>6}{'>' if n == h['line'] else ':'} {s}")


if __name__ == "__main__":
    main()
