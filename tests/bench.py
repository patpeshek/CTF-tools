#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
bench.py — микро-бенчмарки: скорость важных путей и ловля регрессий.

  python bench.py                     # 4 замера, сравнение с baseline
  python bench.py --only lll_27       # один замер
  python bench.py --repeat 5          # больше повторов (медиана)
  python bench.py --update            # записать новый baseline
  python bench.py --json              # машинный вывод
  python bench.py --strict            # код 1, если есть регрессия

Baseline: `tests/bench_baseline.json`. Замеры идут в процессе (без запуска
subprocess), поэтому меряют алгоритм, а не старт интерпретатора.
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
import base64
import importlib.util
import json
import os
import random
import statistics
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
KIT = os.path.dirname(HERE)
BASELINE = os.path.join(HERE, "bench_baseline.json")


def load_kit(rel):
    full = os.path.join(KIT, rel)
    name = "bench_" + os.path.splitext(os.path.basename(full))[0]
    spec = importlib.util.spec_from_file_location(name, full)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _matrix(n, seed=12345):
    rng = random.Random(seed)
    return [[rng.randint(-1000, 1000) for _ in range(n)] for _ in range(n)]


def _prepare():
    """Один раз готовим входы (чтобы не мерять генерацию данных)."""
    rsa = load_kit("crypto/rsa_tool.py")
    common = load_kit("common.py")

    m27 = _matrix(27)
    m48 = _matrix(48, seed=777)

    text_1mb = (b"line without anything special 0123456789\n" * 22000)[:1_000_000]
    big_text = text_1mb + b"CTF{bench_marker}\n" + text_1mb[:1000]

    b64_4kb = base64.b64encode(os.urandom(3000)).decode()

    def lll_27():
        rsa.lll([row[:] for row in m27])

    def lll_48():
        rsa.lll([row[:] for row in m48])

    def find_flags_1mb():
        common.find_flags(big_text)

    def decode_auto_4kb():
        common.decode_auto(b64_4kb)

    return {
        "lll_27": lll_27,
        "lll_48": lll_48,
        "find_flags_1mb": find_flags_1mb,
        "decode_auto_4kb": decode_auto_4kb,
    }


def measure(fn, repeat):
    samples = []
    for _ in range(max(1, repeat)):
        t0 = time.perf_counter()
        fn()
        samples.append(time.perf_counter() - t0)
    return statistics.median(samples), samples


def load_baseline():
    try:
        with open(BASELINE, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def main():
    ap = argparse.ArgumentParser(
        prog="bench.py", description="микро-бенчмарки кита и сравнение с baseline")
    ap.add_argument("--only", default="", help="через запятую: какие замеры")
    ap.add_argument("--repeat", type=int, default=3)
    ap.add_argument("--update", action="store_true", help="перезаписать baseline")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--strict", action="store_true",
                    help="код 1 при регрессии больше порога")
    args = ap.parse_args()

    cases = _prepare()
    chosen = [c.strip() for c in args.only.split(",") if c.strip()] or list(cases)
    unknown = [c for c in chosen if c not in cases]
    if unknown:
        print(f"[-] неизвестные замеры: {', '.join(unknown)}")
        print(f"    есть: {', '.join(cases)}")
        return 2

    base = load_baseline().get("cases", {})
    results, regressions = {}, []

    for name in chosen:
        median, samples = measure(cases[name], args.repeat)
        results[name] = {"median": round(median, 6), "samples": len(samples)}
        old = base.get(name, {}).get("median")
        if old:
            delta = (median - old) / old
            results[name]["baseline"] = old
            results[name]["delta"] = round(delta, 3)
            if delta > 0.20:
                regressions.append(name)

    if args.update:
        payload = {"generated": time.strftime("%Y-%m-%d %H:%M:%S"),
                   "cases": {k: {"median": v["median"]} for k, v in results.items()}}
        with open(BASELINE, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)
        if not args.json:
            print(f"[+] baseline обновлён: {BASELINE}")

    if args.json:
        print(json.dumps({"cases": results, "regressions": regressions},
                         ensure_ascii=False, indent=2))
        return 1 if (args.strict and regressions) else 0

    print(f"[+] замеров: {len(results)}, повторов: {max(1, args.repeat)}")
    for name, res in results.items():
        line = f"  {name:18s} {res['median']:8.4f} s"
        if "baseline" in res:
            pct = res["delta"] * 100
            mark = "↑" if pct > 20 else ("↓" if pct < -10 else "=")
            line += f"   baseline {res['baseline']:.4f}  {mark} {pct:+.0f}%"
        print(line)
    if regressions:
        print(f"\n[!] медленнее baseline (>20%): {', '.join(regressions)}")
        print("    если это ожидаемо — python bench.py --update")
    elif base or args.update:
        print("\n[=] регрессий нет")
    else:
        print("\n[i] baseline ещё нет: python bench.py --update")
    return 1 if (args.strict and regressions) else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except BrokenPipeError:
        sys.exit(0)
