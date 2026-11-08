#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""nearlines.py — задачи вида «100000 одинаковых строк, одна отличается».

Классика foren/misc: файл из N почти одинаковых строк («I WILL NOT ...»),
в каждой уникальной строке изменён ровно один символ, а вместе они
складываются в флаг. Скрипт находит базовую строку, собирает уникальные
и печатает изменённые символы в порядке появления в файле.

  python nearlines.py file.txt
  python nearlines.py file.txt --unique      # просто уникальные строки
  python nearlines.py file.txt --positions   # позиции изменений
"""
from __future__ import annotations

import argparse
import os
import sys
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import common  # noqa: E402


def load(path):
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return f.read().splitlines()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("file")
    ap.add_argument("--unique", action="store_true", help="только уникальные строки")
    ap.add_argument("--positions", action="store_true", help="позиции изменений")
    ap.add_argument("--max-lines", type=int, default=2_000_000)
    common.add_flag_args(ap)
    args = ap.parse_args()
    common.apply_flag_args(args)

    lines = load(args.file)[: args.max_lines]
    if not lines:
        print("[-] пустой файл")
        return
    cnt = Counter(lines)
    print(f"[i] строк: {len(lines)}, уникальных: {len(cnt)}")

    if args.unique:
        for line in dict.fromkeys(lines):
            if cnt[line] == 1:
                print(line)
        return

    base, base_n = cnt.most_common(1)[0]
    print(f"[i] базовая строка ({base_n} повторов): {base!r}")

    # уникальные строки в порядке первого появления
    rows = []          # (строка_в_файле, позиция, символ, строка)
    seen = set()
    for idx, line in enumerate(lines):
        if line == base or line in seen:
            continue
        seen.add(line)
        if len(line) != len(base):
            continue
        diff = [i for i in range(len(base)) if line[i] != base[i]]
        if len(diff) == 1:
            rows.append((idx, diff[0], line[diff[0]], line))

    if not rows:
        # fallback: любые уникальные строки как есть
        uniq = [l for l in dict.fromkeys(lines) if cnt[l] == 1]
        print(f"[i] строк с одним отличием нет; уникальных строк: {len(uniq)}")
        for l in uniq[:200]:
            print("   ", l)
        return

    chars = "".join(r[2] for r in rows)
    print(f"[+] изменённых строк: {len(rows)}")
    print(f"[+] символы в порядке файла: {chars}")
    print(f"[+] символы в обратном порядке: {chars[::-1]}")
    if args.positions:
        print("[i] позиции:", [r[1] for r in rows])
        print("[i] номера строк:", [r[0] for r in rows])
    for f in common.find_flags(chars.encode()):
        print(f"[!!!] ФЛАГ: {f}")


if __name__ == "__main__":
    main()
