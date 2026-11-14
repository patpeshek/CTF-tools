"""solve_both.py — два прогона одновременно: обычный и с ИИ-порядком шагов.

Зачем: правила и модель ошибаются по-разному, и спорить «кто лучше» без
одновременного замера бессмысленно. Скрипт запускает два независимых
солвера на одну и ту же цель:

  * `solve.py <target>`          — как всегда, порядок из правил;
  * `solve.py <target> --ai`     — тот же набор шагов, но модель решает,
                                   что пробовать первым.

Оба пишут поток событий (`--events -`), из него берём флаги, число шагов и
время. В конце — таблица и победитель.

  python solve_both.py "F:\\...\\task" --time 60
  python solve_both.py "F:\\...\\task" --time 60 --expect CTF{...}
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import threading
import time

ROOT = os.path.dirname(os.path.abspath(__file__))


def run(target, ai, budget, results, key, desc_file=""):
    cmd = [sys.executable, os.path.join(ROOT, "solve.py"), target,
           "--time", str(budget), "--events", "-"]
    if ai:
        cmd.append("--ai")
    if desc_file:
        cmd += ["--desc-file", desc_file]
    t0 = time.time()
    res = {"flags": [], "steps": 0, "seconds": 0.0, "rc": 0, "tail": []}
    with subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          text=True, encoding="utf-8", errors="replace",
                          cwd=ROOT) as proc:
        for line in proc.stdout:
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue
            kind = ev.get("event")
            if kind == "step_start":
                res["steps"] += 1
            elif kind == "flag":
                for f in ev.get("flags") or [ev.get("flag")]:
                    if f and f not in res["flags"]:
                        res["flags"].append(f)
            elif kind == "done":
                res["tail"].append(ev.get("status") or "")
        proc.wait()
        res["rc"] = proc.returncode
    res["seconds"] = round(time.time() - t0, 1)
    results[key] = res


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("target")
    ap.add_argument("--time", type=float, default=60)
    ap.add_argument("--expect", default="", help="ожидаемый флаг (если известен)")
    ap.add_argument("--desc-file", default="", help="файл с условием задачи")
    args = ap.parse_args()

    results = {}
    threads = [threading.Thread(target=run, args=(args.target, False, args.time,
                                                  results, "rules", args.desc_file)),
               threading.Thread(target=run, args=(args.target, True, args.time,
                                                  results, "ai", args.desc_file))]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    rules, ai = results.get("rules", {}), results.get("ai", {})
    print()
    print(f"{'':12s} {'флаг':38s} {'шагов':>6s} {'сек':>6s}")
    for name, r in (("правила", rules), ("ИИ-порядок", ai)):
        flag = (r.get("flags") or ["—"])[0]
        mark = ""
        if args.expect and r.get("flags"):
            mark = " ✓" if args.expect in r["flags"] else " ✗"
        print(f"{name:12s} {(flag + mark):38s} {r.get('steps', 0):6d} "
              f"{r.get('seconds', 0):6.1f}")

    def won(r):
        if args.expect:
            return args.expect in (r.get("flags") or [])
        return bool(r.get("flags"))

    print()
    if won(rules) and won(ai):
        w = "правила" if rules["seconds"] <= ai["seconds"] else "ИИ"
        print(f"[=] обе нашли флаг; быстрее {w} "
              f"({min(rules['seconds'], ai['seconds']):.1f} с)")
    elif won(ai):
        print("[=] флаг нашёл только ИИ-порядок")
    elif won(rules):
        print("[=] флаг нашли только правила")
    else:
        print("[=] никто не нашёл — смотри полные логи, тут нечем хвастаться")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
