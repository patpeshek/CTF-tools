#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
flag_hunt.py — найти файлы-флаги по имени и содержимому (оффлайн/дамп).

  python flag_hunt.py dump
  python flag_hunt.py / --all
  python flag_hunt.py dump --json
  python flag_hunt.py dump --pattern "secret*" --pattern "*.key"

Ищет:
  * имена: flag, flag.txt, flag_<random>, *flag*, user.txt, root.txt;
  * содержимое: CTF{...}, flag{...} и любые word{...} (по настройке префиксов);
  * печатает путь, размер, права, владельца и первые байты.
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
import stat
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import common  # noqa: E402

NAME_RE = re.compile(r"(?i)(^|[_\-.])flag([_\-.]|$)|flag|user\.txt|root\.txt")


def looks_like_flag_name(name: str):
    low = name.lower()
    return ("flag" in low) or low in ("user.txt", "root.txt")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("path")
    ap.add_argument("--all", action="store_true", help="не ограничивать глубину/размеры")
    ap.add_argument("--max-size", type=int, default=2, help="МБ на файл для чтения")
    ap.add_argument("--depth", type=int, default=8)
    ap.add_argument("--pattern", action="append", default=[])
    ap.add_argument("--json", action="store_true")
    common.add_flag_args(ap)
    args = ap.parse_args()
    common.apply_flag_args(args)

    patterns = [re.compile(p, re.I) for p in args.pattern]
    root = os.path.abspath(args.path)
    found = []
    base_depth = root.rstrip(os.sep).count(os.sep)

    for cur, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in ("proc", "sys", "dev", "run")]
        depth = cur.count(os.sep) - base_depth
        if not args.all and depth > args.depth:
            dirs[:] = []
            continue
        for name in files:
            path = os.path.join(cur, name)
            try:
                st = os.stat(path)
            except OSError:
                continue
            hit_name = looks_like_flag_name(name) or any(p.search(name) for p in patterns)
            size = st.st_size
            content_flags = []
            snippet = ""
            if size <= args.max_size * 1024 * 1024 and stat.S_ISREG(st.st_mode):
                try:
                    data = open(path, "rb").read(args.max_size * 1024 * 1024)
                    content_flags = common.find_flags(data)
                    if hit_name or content_flags:
                        snippet = data[:300].decode("utf-8", "replace")
                except OSError:
                    pass
            if hit_name or content_flags:
                found.append({
                    "path": path,
                    "size": size,
                    "mode": stat.filemode(st.st_mode),
                    "mtime": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(st.st_mtime)),
                    "name_hit": hit_name,
                    "flags": content_flags,
                    "snippet": snippet.replace("\n", "\\n")[:300],
                })

    print(f"[+] найдено: {len(found)}")
    for x in found:
        print(f"\n{x['path']}")
        print(f"  {x['mode']}  {x['size']} b  {x['mtime']}")
        if x["flags"]:
            print("  FLAGS:", " | ".join(x["flags"]))
        if x["snippet"]:
            print("  head :", x["snippet"])

    if args.json:
        print(json.dumps(found, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
