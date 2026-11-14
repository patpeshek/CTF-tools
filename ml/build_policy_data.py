"""build_policy_data.py — превратить трассы в датасет «состояние + действие → успех».

Трассы (`ml/collect.py`) — это то, как задачи решаются на самом деле: для
каждой задачи список шагов, какие инструменты пробовали и на каком пришёл
флаг. Из них делается обучающий набор для **политики**: для пары
(задача, инструмент) — сработал он или нет.

  python ml/build_policy_data.py --traces F:\\...\\traces_big.jsonl ^
      --out F:\\AIproject\\ml-runs\\policy_v1.npz
"""
from __future__ import annotations

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import numpy as np

from features import byte_hist, hand_features

MAX_TOOLS = 48
SUSPECT = ("REDACTED", "YOUR_FLAG", "not_the_flag", "flag_here", "example")
FLAG_RE = __import__("re").compile(r"^[A-Za-z][A-Za-z0-9_]{1,15}\{([^{}\r\n]{4,80})\}$")


def plausible_flag(flag: str) -> bool:
    """Флаг должен быть похож на настоящий: тело из букв/цифр/подчёркиваний.

    Сборщик запускает solve.py с `--any-prefix`, поэтому в трассы попадает
    мусор вида `Ctf{4tfdyi|4kojz<sgq}`. Учить политику на нём нельзя:
    модель выучит шум вместо «этот шаг сработал».
    """
    if any(s.lower() in flag.lower() for s in SUSPECT):
        return False
    m = FLAG_RE.match(flag.strip())
    if not m:
        return False
    body = m.group(1)
    good = sum(c.isalnum() or c in "_-!." for c in body)
    return good / len(body) >= 0.9


def main_file(task_dir: str, files: list) -> str:
    """Главный файл задачи: самый крупный из мелких (не архив целиком)."""
    best, best_size = "", -1
    for name in files[:40]:
        p = os.path.join(task_dir, name)
        try:
            size = os.path.getsize(p)
        except OSError:
            continue
        if size > 8 * 1024 * 1024:
            continue
        score = size if size < 2 * 1024 * 1024 else 2 * 1024 * 1024
        if score > best_size:
            best, best_size = p, score
    return best


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--traces", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    rows = []
    with open(args.traces, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    print(f"[+] задач в трассах: {len(rows)}")

    # первый проход: какие инструменты встречаются
    counts = {}
    for t in rows:
        for s in t.get("steps") or []:
            counts[s.get("tool", "?")] = counts.get(s.get("tool", "?"), 0) + 1
    tools = [name for name, _ in sorted(counts.items(), key=lambda kv: -kv[1])[:MAX_TOOLS]]
    tool_idx = {name: i for i, name in enumerate(tools)}
    print(f"[+] инструментов: {len(tools)} (взяты самые частые из {len(counts)})")

    X, y, groups = [], [], []
    tasks_used = 0
    for ti, task in enumerate(rows):
        steps = task.get("steps") or []
        if not steps:
            continue
        task_dir = task.get("dir") or task.get("task") or ""
        best = main_file(task_dir, task.get("files") or [])
        try:
            with open(best, "rb") as fh:
                data = fh.read(8 * 1024 * 1024)
        except OSError:
            continue
        state = np.concatenate([hand_features(data), byte_hist(data)]).astype(np.float32)
        tasks_used += 1
        n = len(steps)
        for si, st in enumerate(steps):
            tool = st.get("tool", "?")
            if tool not in tool_idx:
                continue
            onehot = np.zeros(MAX_TOOLS, dtype=np.float32)
            onehot[tool_idx[tool]] = 1.0
            flags = st.get("flags") or []
            good = [f for f in flags if plausible_flag(f)]
            # ВАЖНО: только то, что известно ДО запуска шага.
            # status и число флагов — следствие, а не признак: с ними модель
            # «предсказывала» уже случившееся (фиктивные 0.96 top-1).
            extra = np.array([si / max(1, n)], dtype=np.float32)
            X.append(np.concatenate([state, onehot, extra]))
            y.append(1.0 if good else 0.0)
            groups.append(ti)

    if not X:
        print("[-] не из чего собрать датасет")
        return 1
    X = np.stack(X)
    y = np.array(y, dtype=np.float32)
    groups = np.array(groups, dtype=np.int32)
    print(f"[+] пар (задача, шаг): {len(y)}, задач с файлами: {tasks_used}")
    print(f"[+] доля успешных шагов: {y.mean():.3f}")
    np.savez(args.out, X=X, y=y, groups=groups, tools=np.array(tools),
             task_ids=np.array([t.get("task", "") for t in rows], dtype=object))
    print(f"[+] сохранено → {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
