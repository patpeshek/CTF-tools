"""chain_eval.py — измеряем `crypto/chain.py` на задачах с известными флагами.

Зачем: `chain` числится в `WEAK_TOOLS` (его флаги демотируются), потому что
раньше он выдавал мусор. Но насколько именно он точен? Без числа это вера, а
не инженерия. Скрипт берёт набор задач, где ответ известен, гоняет по ним
`chain.search` и считает:

  * recall   — нашли ли настоящий флаг;
  * precision — доля возвращённых флагов, которые действительно ответ;
  * мусор    — сколько ложных флагов прилетело вместе с правильным;
  * время    — сколько это стоит.

Запуск:

  python tests/chain_eval.py
  python tests/chain_eval.py --dir F:\\AIproject\\_scratch\\custom_tasks ^
      --limit 8 --time 6
"""
from __future__ import annotations

import argparse
import os
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "crypto"))

import chain  # noqa: E402  (путь добавлен выше)

DEFAULT_DIR = r"F:\AIproject\_scratch\custom_tasks"
SKIP_DIRS = {"_answers", "_build"}


def read_answer(path: str) -> str:
    with open(path, encoding="utf-8", errors="replace") as fh:
        return fh.read().strip()


def task_dirs(root: str):
    for name in sorted(os.listdir(root)):
        p = os.path.join(root, name)
        if os.path.isdir(p) and name not in SKIP_DIRS:
            yield name, p


def files_of(task_dir: str):
    out = []
    for dirpath, _dirs, names in os.walk(task_dir):
        for n in sorted(names):
            p = os.path.join(dirpath, n)
            if os.path.isfile(p):
                out.append(p)
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", default=DEFAULT_DIR)
    ap.add_argument("--limit", type=int, default=0, help="только первые N задач")
    ap.add_argument("--time", type=float, default=8.0, help="лимит на файл, сек")
    ap.add_argument("--quiet", action="store_true", help="без построчных файлов")
    args = ap.parse_args()

    answers_dir = os.path.join(args.dir, "_answers")
    if not os.path.isdir(answers_dir):
        print(f"[-] нет папки с ответами: {answers_dir}")
        return 2

    tasks = list(task_dirs(args.dir))
    if args.limit:
        tasks = tasks[:args.limit]
    print(f"[+] задач: {len(tasks)}, лимит на файл: {args.time:.0f} c", flush=True)

    n_found = n_tasks = 0
    returned = true_pos = 0
    junk_examples = []
    lines = []
    t0 = time.time()

    for name, path in tasks:
        ans_file = os.path.join(answers_dir, name + ".txt")
        if not os.path.exists(ans_file):
            lines.append((name, "-", "нет ответа", 0, 0.0))
            continue
        answer = read_answer(ans_file)
        n_tasks += 1
        hit_file, hit_ms, n_flags, n_junk = None, 0.0, 0, 0
        for f in files_of(path):
            rel = os.path.relpath(f, path)
            if os.path.getsize(f) > 32 * 1024 * 1024:
                continue
            data = open(f, "rb").read()
            t = time.time()
            try:
                res = chain.search(data, time_limit=args.time)
            except Exception as exc:  # один битый файл не должен рушить замер
                if not args.quiet:
                    print(f"    [!] {name}/{rel}: {exc}", flush=True)
                continue
            dt = time.time() - t
            flags = list(getattr(res, "flags", []) or [])
            if res.flag and res.flag not in flags:
                flags.insert(0, res.flag)
            returned += len(flags)
            if answer in flags:
                true_pos += 1
                if hit_file is None:
                    hit_file, hit_ms = rel, dt * 1000
                n_flags += 1
            else:
                n_junk += len(flags)
                if flags and len(junk_examples) < 8:
                    junk_examples.append((name, rel, flags[:2]))
            if not args.quiet:
                mark = "OK " if answer in flags else ("мусор" if flags else "  - ")
                extra = f" {flags[:2]}" if flags and answer not in flags else ""
                print(f"    {mark} {rel:40s} {dt * 1000:7.0f} мс{extra}", flush=True)
        if hit_file:
            n_found += 1
        lines.append((name, "да" if hit_file else "нет", hit_file or "-", n_junk, hit_ms))

    print(flush=True)
    print(f"{'задача':34s} {'нашли':6s} {'чем':38s} {'мусор':6s} {'мс':>7s}")
    for name, ok, where, junk, ms in lines:
        print(f"{name:34s} {ok:6s} {where:38s} {junk:6d} {ms:7.0f}")

    precision = true_pos / max(1, returned)
    print(flush=True)
    print(f"[=] recall: {n_found}/{n_tasks} задач = {n_found / max(1, n_tasks):.0%}")
    print(f"[=] precision (флагов всего {returned}, из них настоящих {true_pos}): "
          f"{precision:.0%}")
    print(f"[=] время: {time.time() - t0:.1f} c на {n_tasks} задач")
    if junk_examples:
        print("[=] примеры мусора:")
        for name, rel, flags in junk_examples:
            print(f"    {name}/{rel}: {flags}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
