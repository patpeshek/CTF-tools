"""mine.py — прогнать реальный архив задач и найти, где кит ошибается.

Зачем: скачанные задачи почти всегда без флагов, но они дают то, чего нет в
синтетике — **настоящие байты**. Скрипт идёт по дереву и для каждого файла:

  * определяет тип по сигнатуре (`eval_true.expected`);
  * прогоняет `crypto/chain` с маленьким бюджетом и смотрит, что он выдаёт;
  * ловит падения, таймауты и «нашёл флаг за 0.01 с на случайных данных»
    (это либо настоящая утечка, либо приманка, либо ложное срабатывание).

Результат — JSONL по файлам + сводка. Из неё видно, какие семейства кит
вообще не понимает и где он врёт, а не «на глаз».

  python ml/mine.py --root F:\\AIproject\\ctf-archives\\ctfs ^
      --out F:\\AIproject\\ml-runs\\mine.jsonl --time 2
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(ROOT, "crypto"))

from eval_true import expected  # noqa: E402

try:
    import chain  # noqa: E402
except Exception:  # нет зависимостей — майнинг без chain
    chain = None

SKIP_EXT = {".pyc", ".pyo", ".so", ".dll", ".exe", ".class"}
MAX_SIZE = 16 * 1024 * 1024


def walk(root):
    for dirpath, dirs, names in os.walk(root):
        dirs[:] = [d for d in dirs if d not in (".git", "__pycache__")]
        for n in sorted(names):
            p = os.path.join(dirpath, n)
            try:
                size = os.path.getsize(p)
            except OSError:
                continue
            if 0 < size <= MAX_SIZE:
                yield p, size


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--time", type=float, default=2.0, help="лимит chain на файл")
    ap.add_argument("--no-chain", action="store_true", help="только метки, без поиска")
    args = ap.parse_args()

    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    n = 0
    stats = {}
    flags = {}
    crashes = 0
    t0 = time.time()
    with open(args.out, "w", encoding="utf-8") as fh:
        for p, size in walk(args.root):
            try:
                with open(p, "rb") as f:
                    data = f.read(MAX_SIZE)
            except OSError:
                continue
            label = expected(data, p)
            rec = {"path": p, "size": size, "label": label, "flags": [],
                   "ms": 0.0, "error": ""}
            if chain is not None and not args.no_chain:
                t = time.time()
                try:
                    res = chain.search(data, time_limit=args.time)
                    found = list(getattr(res, "flags", []) or [])
                    if res.flag and res.flag not in found:
                        found.insert(0, res.flag)
                    rec["flags"] = found[:3]
                    for fl in found:
                        flags[fl] = flags.get(fl, 0) + 1
                except Exception as exc:  # падение инструмента — тоже находка
                    rec["error"] = f"{type(exc).__name__}: {exc}"
                    crashes += 1
                rec["ms"] = round((time.time() - t) * 1000, 1)
            stats[label] = stats.get(label, 0) + 1
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
            n += 1
            if n % 200 == 0:
                print(f"  {n} файлов, {time.time() - t0:.0f} c", flush=True)
            if args.limit and n >= args.limit:
                break

    print(f"\n[=] файлов: {n}, падений: {crashes}, время: {time.time() - t0:.0f} c")
    print("[=] по типам:")
    for k, v in sorted(stats.items(), key=lambda kv: -kv[1]):
        print(f"    {k:12s} {v}")
    if flags:
        print(f"[=] уникальных флагов из chain: {len(flags)}")
        for fl, cnt in sorted(flags.items(), key=lambda kv: -kv[1])[:10]:
            print(f"    {cnt:4d}× {fl[:70]}")
    print(f"[+] построчно: {args.out}")


if __name__ == "__main__":
    main()
