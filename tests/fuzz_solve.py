#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
fuzz_solve.py — прогоняет solve по сгенерированным мини-таскам.

  python tests/gen_challenges.py --out ... --seed 1
  python tests/fuzz_solve.py --dir ... --time 45

Сравнивает с manifest.json (ожидаемые флаги) и печатает статистику по типам.
Сами флаги в консоль не выводятся.
"""
from __future__ import annotations

try:
    import sys as _sys
    for _stream in (_sys.stdout, _sys.stderr):
        _stream.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

import argparse
import json
import os
import subprocess
import sys

KIT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", required=True)
    ap.add_argument("--time", default="45")
    ap.add_argument("--only", nargs="*", help="фильтр по типу таска")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    mp = os.path.join(args.dir, "manifest.json")
    if not os.path.exists(mp):
        print("[-] нет manifest.json — сначала gen_challenges.py")
        return
    tasks = json.load(open(mp, encoding="utf-8"))
    if args.only:
        tasks = [t for t in tasks if t["kind"] in args.only]

    rows = []
    for t in tasks:
        target = os.path.join(args.dir, t["dir"])
        r = subprocess.run([sys.executable, os.path.join(KIT, "toolbox.py"),
                            "solve", target, "--time", args.time],
                           capture_output=True, timeout=600)
        out = (r.stdout + r.stderr).decode("utf-8", "replace")
        ok = t["flag"] in out
        rows.append((t["kind"], ok))
        print(f"{'OK ' if ok else ' - '}{t['kind']:14s} {t['dir']}")
        if not ok and args.verbose:
            for line in out.strip().splitlines()[-5:]:
                print("      " + line[:140])

    ok_n = sum(1 for _, ok in rows if ok)
    print(f"\nитого: {ok_n}/{len(rows)}")
    by_kind = {}
    for kind, ok in rows:
        tot, good = by_kind.get(kind, (0, 0))
        by_kind[kind] = (tot + 1, good + (1 if ok else 0))
    for kind, (tot, good) in sorted(by_kind.items(), key=lambda x: x[1][1] / x[1][0]):
        print(f"  {kind:14s} {good}/{tot}")


if __name__ == "__main__":
    main()
