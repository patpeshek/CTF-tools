"""suite_eval.py — прогон всего набора учебных задач через `solve.py`.

Считает главное: сколько задач реально решается и за сколько секунд. Ответы
берутся из `_answers/<task>.txt`, флаг ищется в выводе `solve.py`.

  python tests/suite_eval.py
  python tests/suite_eval.py --dir F:\\AIproject\\_scratch\\custom_tasks --time 90
"""
from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FLAG_RE = re.compile(r"[A-Za-z][A-Za-z0-9_]{1,15}\{[^{}\r\n]{1,120}\}")
DEFAULT_DIR = r"F:\AIproject\_scratch\custom_tasks"
SKIP = {"_answers", "_build"}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", default=DEFAULT_DIR)
    ap.add_argument("--time", type=int, default=60, help="лимит solve.py на задачу")
    ap.add_argument("--only", default="", help="подстрока в имени задачи")
    args = ap.parse_args()

    answers = os.path.join(args.dir, "_answers")
    tasks = [d for d in sorted(os.listdir(args.dir))
             if os.path.isdir(os.path.join(args.dir, d)) and d not in SKIP
             and args.only in d]
    print(f"[+] задач: {len(tasks)}, лимит {args.time} c на задачу", flush=True)

    ok = 0
    total_time = 0.0
    rows = []
    for name in tasks:
        ann = os.path.join(answers, name + ".txt")
        expect = ""
        if os.path.exists(ann):
            with open(ann, encoding="utf-8", errors="replace") as fh:
                expect = fh.read().strip()
        t0 = time.time()
        proc = subprocess.run(
            [sys.executable, os.path.join(ROOT, "solve.py"),
             os.path.join(args.dir, name), "--time", str(args.time)],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            cwd=ROOT)
        dt = time.time() - t0
        total_time += dt
        found = FLAG_RE.findall(proc.stdout or "")
        hit = bool(expect) and expect in found
        ok += hit
        rows.append((name, hit, expect, found[:2], dt))
        mark = "OK   " if hit else ("ФЛАГ!" if found else "нет  ")
        print(f"  {mark} {name:34s} {dt:6.1f} c  "
              f"{found[0] if found else '-'}", flush=True)

    print(flush=True)
    print(f"[=] решено: {ok}/{len(tasks)} за {total_time:.0f} c "
          f"({total_time / max(1, len(tasks)):.1f} c на задачу)")
    wrong = [(n, f, e) for n, h, e, f, _ in rows if f and not h]
    if wrong:
        print("[=] найден не тот флаг:")
        for name, found, expect in wrong:
            print(f"    {name}: получили {found[0]}, ждали {expect}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
