#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""corpus_bench.py — прогон кита по корпусу настоящих задач.

Корпус: `tests/corpus/manifest.json` (задача -> файлы, категория, эталонный флаг).
Отчёт: PASS/FAIL по каждой задаче, сводка по категориям, маскированные флаги.

    python tests/corpus_bench.py --list
    python tests/corpus_bench.py --only xor,crabby
    python tests/corpus_bench.py --category crypto --jobs 3
    python tests/corpus_bench.py --timeout 60 --json out.json
"""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import json
import os
import re
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
KIT = os.path.dirname(HERE)
MANIFEST = os.path.join(HERE, "corpus", "manifest.json")
PY = sys.executable


def mask(flag):
    """Не печатать флаги публичных задач целиком."""
    if not flag:
        return "-"
    m = re.match(r"([A-Za-z0-9_]+)\{(.*)\}", flag)
    if not m:
        return flag[:6] + "…"
    body = m.group(2)
    keep = body[:3] if len(body) > 8 else body[:1]
    return f"{m.group(1)}{{{keep}…}}"


def load_manifest(path=MANIFEST):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def find_flag(text, expected):
    if expected and expected in text:
        return expected
    for m in re.finditer(r"[A-Za-z][A-Za-z0-9_]{1,20}\{[^|\n]{3,200}\}", text):
        cand = m.group()
        if expected and cand.strip() == expected:
            return cand
        if expected and cand.strip().lower() == expected.lower():
            return cand
    return None


def near_flag(text, expected):
    """Похоже на флаг, но OCR/PDF исказили символы? Не PASS, но и не провал."""
    if not expected:
        return None
    import difflib
    best = (0.0, None)
    for m in re.finditer(r"[A-Za-z][A-Za-z0-9_]{1,20}\{[^|\n]{3,200}\}", text):
        ratio = difflib.SequenceMatcher(None, expected.lower(),
                                        m.group().lower()).ratio()
        if ratio > best[0]:
            best = (ratio, m.group())
    return best if best[0] >= 0.80 else None


def run_task(task, root, timeout, deep, tool):
    target = task["target"]
    if root and not os.path.isabs(target):
        target = os.path.join(root, target.replace("/", os.sep))
    cmd = [PY, os.path.join(KIT, "toolbox.py"), tool, target,
           "--time", str(timeout), "--any-prefix", "--jobs", "2"]
    if deep and tool == "solve":
        cmd.append("--deep")
    env = dict(os.environ, PYTHONUTF8="1", PYTHONIOENCODING="utf-8")
    t0 = time.time()
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8",
                           errors="replace", timeout=timeout + 45, env=env)
        out = (p.stdout or "") + "\n" + (p.stderr or "")
        rc = p.returncode
    except subprocess.TimeoutExpired as e:
        out = ((e.stdout or "") if isinstance(e.stdout, str) else "") + "\nTIMEOUT"
        rc = -9
    dt = time.time() - t0
    got = find_flag(out, task.get("flag"))
    near = None
    if not got:
        near = near_flag(out, task.get("flag"))
    status = "PASS" if got else ("TIMEOUT" if rc == -9 else ("NEAR" if near else "FAIL"))
    return {
        "id": task["id"],
        "category": task["category"],
        "points": task.get("points"),
        "target": task["target"],
        "status": status,
        "near": round(near[0], 2) if near else None,
        "seconds": round(dt, 1),
        "flag": mask(task.get("flag")),
        "expected": mask(got),
        "rc": rc,
        "tail": out.strip().splitlines()[-6:],
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--manifest", default=MANIFEST)
    ap.add_argument("--only", help="id через запятую")
    ap.add_argument("--category", help="категория (rev, crypto, foren, misc)")
    ap.add_argument("--timeout", type=int, default=45, help="бюджет solve на задачу, сек")
    ap.add_argument("--jobs", type=int, default=2)
    ap.add_argument("--deep", action="store_true")
    ap.add_argument("--tool", default="solve", choices=["solve", "auto", "megarev"])
    ap.add_argument("--json", help="куда сохранить результаты")
    ap.add_argument("--list", action="store_true")
    args = ap.parse_args()

    man = load_manifest(args.manifest)
    root = man["root"]
    tasks = man["tasks"]

    if args.list:
        for t in tasks:
            mark = "skip" if t.get("skip") else "test"
            print(f'{mark:5s} {t["id"]:30s} {t["category"]:8s} '
                  f'{str(t.get("points")):>4s}  {t.get("skip") or t["target"]}')
        return 0

    if args.only:
        want = {x.strip() for x in args.only.split(",")}
        tasks = [t for t in tasks if t["id"] in want]
    if args.category:
        tasks = [t for t in tasks if t["category"] == args.category]
    tasks = [t for t in tasks if not t.get("skip")]

    if not tasks:
        print("нет задач под фильтр")
        return 1

    print(f"[i] корпус {man['corpus']}, "
          f"задач: {len(tasks)}, бюджет {args.timeout}s, jobs {args.jobs}")
    results = []
    with cf.ThreadPoolExecutor(max_workers=args.jobs) as ex:
        futs = {ex.submit(run_task, t, root, args.timeout, args.deep, args.tool): t
                for t in tasks}
        for fut in cf.as_completed(futs):
            r = fut.result()
            results.append(r)
            print(f'{r["status"]:7s} {r["id"]:30s} {r["category"]:8s} '
                  f'{r["seconds"]:6.1f}s  {r["flag"]}')

    results.sort(key=lambda r: (r["category"], r["id"]))
    print("\n=== по категориям ===")
    cats = {}
    for r in results:
        c = cats.setdefault(r["category"], [0, 0, 0])
        c[0] += 1
        if r["status"] == "PASS":
            c[1] += 1
        elif r["status"] == "NEAR":
            c[2] += 1
    for c in sorted(cats):
        n, ok, near = cats[c]
        print(f"  {c:8s} {ok}/{n}" + (f"  (+{near} NEAR)" if near else ""))
    ok = sum(1 for r in results if r["status"] == "PASS")
    near = sum(1 for r in results if r["status"] == "NEAR")
    print(f"\n=== ИТОГО: {ok}/{len(results)}" +
          (f", NEAR: {near}" if near else "") + " ===")

    fails = [r for r in results if r["status"] not in ("PASS", "NEAR")]
    if fails:
        print("\n--- провалы (последние строки вывода):")
        for r in fails:
            print(f'\n[{r["id"]}] {r["status"]}  {r["target"]}')
            for line in r["tail"]:
                print("   ", line)

    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump({"corpus": man["corpus"], "at": time.strftime("%Y-%m-%d %H:%M"),
                       "results": results},
                      f, ensure_ascii=False, indent=1)
        print(f"\n[i] сохранено: {args.json}")
    return 0 if ok == len(results) else 2


if __name__ == "__main__":
    sys.exit(main())
