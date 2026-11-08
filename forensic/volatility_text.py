#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
volatility_text.py — разбор текстовых выгрузок Volatility (pstree, envars, cmdline).

  python volatility_text.py windows.envars.txt --name agent
  python volatility_text.py windows.pstree.txt --grep lab
  python volatility_text.py *.txt --keys
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
import glob
import re

KEY_RX = re.compile(r"(?i)\b(key|secret|token|pass|seed|nonce|flag|role|slot)\b")


def blocks_from_envars(lines):
    """Volatility 3 envars: строки вида 'PID  Process  Block  VAR  VALUE'."""
    blocks = {}
    for line in lines:
        parts = re.split(r"\s{2,}|\t", line.strip())
        if len(parts) >= 2 and parts[0].isdigit():
            pid, name = parts[0], parts[1]
            blocks.setdefault((pid, name), []).append(line.rstrip())
        elif len(parts) >= 2 and parts[0].upper().startswith(("PID", "---")):
            continue
    return blocks


def blocks_from_tree(lines):
    """pstree: блоки по строкам с PID и именем процесса."""
    blocks = []
    cur = []
    for line in lines:
        if re.search(r"\b\d{2,6}\b.*\.(exe|dll|bin|py|sh)\b", line, re.I):
            if cur:
                blocks.append(cur)
            cur = [line.rstrip()]
        elif cur:
            cur.append(line.rstrip())
    if cur:
        blocks.append(cur)
    return blocks


def show_block(block, args):
    text = "\n".join(block)
    if args.keys:
        for line in block:
            if KEY_RX.search(line):
                print(line)
        return
    print(text)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("files", nargs="+")
    ap.add_argument("--name", help="подстрока имени процесса")
    ap.add_argument("--grep", help="подстрока в любой строке")
    ap.add_argument("--keys", action="store_true", help="только строки с key/secret/...")
    ap.add_argument("--context", type=int, default=6)
    args = ap.parse_args()

    paths = []
    for f in args.files:
        paths.extend(glob.glob(f))

    for path in paths:
        lines = open(path, encoding="utf-8", errors="replace").read().splitlines()
        env = blocks_from_envars(lines)
        tree = blocks_from_tree(lines)
        printed = False

        if env:
            for (pid, name), block in env.items():
                if args.name and args.name.lower() not in name.lower():
                    continue
                print(f"\n=== {path}: PID {pid} {name} ===")
                show_block(block, args)
                printed = True

        if tree and (args.name or args.grep):
            for block in tree:
                head = block[0]
                if args.name and args.name.lower() not in "\n".join(block).lower():
                    continue
                if args.grep and args.grep.lower() not in "\n".join(block).lower():
                    continue
                print(f"\n=== {path}: {head.strip()[:120]} ===")
                show_block(block[1:1 + args.context], args)
                printed = True

        if (args.grep or args.keys) and not printed:
            # запасной режим: просто контекст вокруг совпадений
            for i, line in enumerate(lines):
                if (args.grep and args.grep.lower() in line.lower()) or (args.keys and KEY_RX.search(line)):
                    print(f"\n=== {path}:{i+1} ===")
                    for j in range(max(0, i - args.context), min(len(lines), i + args.context + 1)):
                        print(lines[j])
                    printed = True

        if not printed:
            print(f"[-] {path}: ничего не найдено")


if __name__ == "__main__":
    main()
