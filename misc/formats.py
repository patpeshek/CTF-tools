#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
formats.py — память о форматах ответа сервиса.

Сервис может помечать буквы как угодно: `Г Ж С`, `+ - .`, `🟩🟨⬛`, `2 1 0`.
Известные варианты разбираются автоматически; незнакомый набор символов
запоминается один раз (спросили у человека) и дальше применяется молча.

  python formats.py --list
  python formats.py --set "ГЖС" --green "Г" --yellow "Ж" --gray "С"
  python formats.py --forget "ГЖС"
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
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CACHE = os.path.join(ROOT, "formats.json")


def _key(symbols) -> str:
    return "".join(sorted({str(s).upper() for s in symbols if str(s).strip()}))


def load(path: str = CACHE) -> dict:
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def save(data: dict, path: str = CACHE):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2, sort_keys=True)


def get(symbols, path: str = CACHE):
    data = load(path)
    key = _key(symbols)
    if key in data:
        return data[key]
    seen = {str(s).upper() for s in symbols if str(s).strip()}
    # набор мог быть записан раньше целиком («012»), а сейчас видно только «0»
    for k, v in data.items():
        if seen and seen <= set(k):
            return v
    return None


def put(symbols, mapping: dict, path: str = CACHE):
    data = load(path)
    data[_key(symbols)] = {str(k).upper(): v for k, v in mapping.items()}
    save(data, path)
    return data[_key(symbols)]


def apply(mapping: dict, raw) -> list[str]:
    """Символы ответа -> g/y/b. Неизвестный символ считаем «нет»."""
    return [mapping.get(str(s).upper(), "b") for s in raw]


def resolve(raw, board: str | None = None, interactive: bool = False):
    """Сырые символы -> вектор g/y/b: из кэша, при необходимости — спросить."""
    mapping = get(raw)
    if mapping is None and interactive:
        mapping = ask(raw, board)
        if mapping:
            put(raw, mapping)
    if not mapping:
        return None
    return apply(mapping, raw)


def ask(symbols, board: str | None = None, stream=None) -> dict | None:
    """Спросить один раз, что значит каждый символ. None — пропустить."""
    stream = stream or sys.stdin
    uniq = sorted({str(s).upper() for s in symbols})
    print("\n[?] Незнакомый формат разметки:", " ".join(uniq))
    if board:
        print(board.rstrip()[:600])
    print("    Для каждого символа: g=на месте, y=есть в слове, b=нет, s=пропустить")
    mapping = {}
    for sym in uniq:
        while True:
            try:
                ans = input(f"    {sym} -> ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                return None
            if ans in ("g", "y", "b"):
                mapping[sym] = ans
                break
            if ans in ("s", "skip", ""):
                return None
    return mapping


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--set")
    ap.add_argument("--green", default="")
    ap.add_argument("--yellow", default="")
    ap.add_argument("--gray", default="")
    ap.add_argument("--forget")
    ap.add_argument("--path", default=CACHE)
    args = ap.parse_args()

    if args.forget:
        data = load(args.path)
        data.pop(_key(args.forget), None)
        save(data, args.path)
        print("[+] забыл", _key(args.forget))
        return
    if args.set:
        mapping = {}
        for ch in args.green:
            mapping[ch] = "g"
        for ch in args.yellow:
            mapping[ch] = "y"
        for ch in args.gray:
            mapping[ch] = "b"
        if not mapping:
            ap.error("нужен хотя бы один из --green/--yellow/--gray")
        put(args.set, mapping, args.path)
        print("[+] запомнил", _key(args.set), mapping)
        return
    data = load(args.path)
    if not data:
        print("[i] пусто:", args.path)
    for k, v in sorted(data.items()):
        print(f"  {k:8} -> {v}")


if __name__ == "__main__":
    main()
