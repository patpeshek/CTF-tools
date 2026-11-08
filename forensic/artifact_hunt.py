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
import os
import re
import sys
import zipfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import common

PATTERNS = [
    ("KV", re.compile(r"(?m)^\s*[A-Z][A-Z0-9_]{2,40}\s*=\s*\S+")),
    ("SECRET", re.compile(r"(?i)\b(key|secret|token|password|passwd|seed|nonce|android_id|"
                          r"machine_id|slot|salt|iv)\b\s*[:=]\s*['\"]?([^\s'\"<>]{4,120})")),
    ("B64", re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")),
    ("HEX", re.compile(r"\b[0-9a-fA-F]{32,}\b")),
]


HITS = []


def scan_text(name, text, args):
    lines = text.splitlines()
    for tag, rx in PATTERNS:
        for m in rx.finditer(text):
            start = max(0, m.start() - 40)
            end = min(len(text), m.end() + 40)
            snippet = text[start:end].replace("\n", " ")[:220]
            line_no = text.count("\n", 0, m.start()) + 1
            HITS.append({"file": name, "line": line_no, "tag": tag,
                         "snippet": snippet})
    for flag in common.find_flags(text.encode("utf-8", "replace")):
        pos = text.find(flag)
        line_no = text.count("\n", 0, pos) + 1 if pos >= 0 else 1
        HITS.append({"file": name, "line": line_no, "tag": "FLAG",
                     "snippet": flag})


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
    ap.add_argument("--context", type=int, default=0)
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


if __name__ == "__main__":
    main()
