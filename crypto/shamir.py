#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
shamir.py — разделение секрета: доли Шамира и CRT-остатки.

  python shamir.py --share "1:0x1f" --share "2:0x2c" --share "3:0x39"
  python shamir.py --file shares.txt --k 2
  python shamir.py --file shares.txt --robust          # одна доля битая
  python shamir.py --crt --mod "3:2" --mod "5:3" --mod "7:2"

Доли: `x:y`, `(x, y)`, `x y`, `x,y` (числа в hex через 0x).
Поле: `--prime p`; по умолчанию подбирается автоматически (проверка по
оставшимся долям), иначе — рациональная интерполяция.

Выход: секрет в десятичном/hex/ASCII виде, проверка «сходится ли с остальными
долями», поиск флага в байтах секрета.
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
import itertools
import json
import os
import re
import sys
from fractions import Fraction

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import common  # noqa: E402

# Поля, которые чаще всего берут в задачах.
COMMON_PRIMES = [
    (1 << 127) - 1,
    (1 << 521) - 1,
    (1 << 607) - 1,
    (1 << 61) - 1,
    (1 << 31) - 1,
    (1 << 255) - 19,
    2 ** 256 - 2 ** 32 - 977,
    (1 << 128) - 159,
]


def _num(text: str) -> int:
    text = text.strip()
    try:
        return int(text, 0)
    except ValueError:
        return int(text)


def parse_shares(pairs):
    """[(x, y)] из строк вида '1:0x1f', '(2, 44)', '3 55'."""
    out = []
    for raw in pairs:
        nums = re.findall(r"-?0[xX][0-9a-fA-F]+|-?\d+", raw)
        if len(nums) != 2:
            raise ValueError(f"не понял долю: {raw!r} (нужно x:y)")
        out.append((_num(nums[0]), _num(nums[1])))
    return out


def parse_shares_from_text(text):
    """Доли из свободного текста: по две числа в строке."""
    out = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or line.startswith("//"):
            continue
        nums = re.findall(r"0[xX][0-9a-fA-F]+|\d+", line)
        if len(nums) == 2:
            out.append((int(nums[0], 0), int(nums[1], 0)))
    return out


def lagrange_at_zero(shares, prime):
    total = 0
    for i, (xi, yi) in enumerate(shares):
        num, den = 1, 1
        for j, (xj, _) in enumerate(shares):
            if i == j:
                continue
            num = (num * (-xj)) % prime
            den = (den * (xi - xj)) % prime
        total = (total + yi * num * pow(den, -1, prime)) % prime
    return total


def lagrange_eval(shares, x, prime):
    total = 0
    for i, (xi, yi) in enumerate(shares):
        num, den = 1, 1
        for j, (xj, _) in enumerate(shares):
            if i == j:
                continue
            num = (num * (x - xj)) % prime
            den = (den * (xi - xj)) % prime
        total = (total + yi * num * pow(den, -1, prime)) % prime
    return total


def rational_at_zero(shares):
    total = Fraction(0)
    for i, (xi, yi) in enumerate(shares):
        num, den = Fraction(1), Fraction(1)
        for j, (xj, _) in enumerate(shares):
            if i == j:
                continue
            num *= -xj
            den *= (xi - xj)
        total += Fraction(yi) * num / den
    return total


def as_bytes(value, max_len=512):
    if value <= 0:
        return b""
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return raw[:max_len]


def printable_ratio(data):
    if not data:
        return 0.0
    good = sum(32 <= b < 127 or b in (9, 10, 13) for b in data)
    return good / len(data)


def describe(value):
    """Число → (hex, ascii-подпись)."""
    raw = as_bytes(value)
    if len(raw) >= 4 and printable_ratio(raw) > 0.85:
        text = raw.decode("latin-1")
        return hex(value), text
    return hex(value), ""


def _best_modular(shares, k, prime):
    """Лучший секрет по k долям + согласие ближайшего конкурента.

    Голосуем не за наборы, а за секреты: разные наборы могут давать один и
    тот же полином (это нормально), а вот два РАЗНЫХ секрета с равным
    согласием — это неоднозначность, её нельзя разрешать угадыванием.
    """
    if k >= len(shares):
        return lagrange_at_zero(shares, prime), len(shares), -1, []

    scores, agree_sets = {}, {}
    for combo in itertools.combinations(range(len(shares)), k):
        subset = [shares[i] for i in combo]
        try:
            cand = lagrange_at_zero(subset, prime)
            agree = [i for i, (x, y) in enumerate(shares)
                     if lagrange_eval(subset, x, prime) == y % prime]
        except (ValueError, ZeroDivisionError):
            continue
        if cand not in scores or len(agree) > scores[cand]:
            scores[cand] = len(agree)
            agree_sets[cand] = agree

    if not scores:
        return None, -1, -1, []
    leader = max(scores, key=lambda secret: scores[secret])
    runner_up = max((v for s, v in scores.items() if s != leader), default=-1)
    return leader, scores[leader], runner_up, agree_sets[leader]


def solve_shamir(shares, prime=None, k=None, robust=False):
    shares = list(shares)
    if len(shares) < 2:
        raise ValueError("нужно минимум 2 доли")
    if k is None or k < 2 or k > len(shares):
        k = len(shares)

    # Рациональная интерполяция: если секрет меньше поля, модуль не при делах
    # и результат получается целым — это самый частый CTF-случай.
    rational = None
    try:
        frac = rational_at_zero(shares[:k])
        if frac.denominator == 1:
            rational = int(frac)
    except (ZeroDivisionError, ValueError):
        rational = None

    candidates = []
    if prime:
        primes = [prime]
    else:
        # В схеме Шамира y < p, поэтому поле обязано быть больше всех долей:
        # иначе «согласие» получается случайно (сравнение идёт по модулю p).
        biggest = max(abs(y) for _, y in shares)
        primes = [p for p in COMMON_PRIMES if p > biggest]
        if k == len(shares):
            primes = primes[:1]  # при k == n модуль не определить

    for p in primes:
        try:
            cand, agree, second, agree_idx = _best_modular(shares, k, p)
        except (ValueError, ZeroDivisionError):
            continue
        if cand is None:
            continue
        candidates.append(dict(prime=p, secret=cand, agree=agree,
                               second=second, agree_idx=agree_idx))

    if not prime and not primes:
        raise ValueError(
            "доли больше всех известных полей — укажи --prime (модуль схемы)")

    if k < len(shares):
        # Модуль определяется только по согласию долей.
        if not candidates:
            raise ValueError("не сходится: ни одно поле не подошло — проверь доли")
        candidates.sort(key=lambda c: (c["agree"], c["prime"]), reverse=True)
        best = candidates[0]
        need = max(k, len(shares) // 2 + 1)
        if best["agree"] < need:
            raise ValueError(
                f"не сходится: максимум согласных долей {best['agree']} "
                f"из {len(shares)} (нужно {need})")
        # Однозначность: иначе второй набор даёт другой секрет, и выбирать
        # «на глаз» нельзя — честно просим ещё долей.
        if best["second"] >= best["agree"]:
            raise ValueError(
                f"неоднозначно: два набора долей дают одинаковое согласие "
                f"({best['agree']} из {len(shares)}). Нужны лишние доли "
                f"(не меньше k+2), иначе ошибку не отличить от правды")
        chosen, secret = best["prime"], best["secret"]
        note = ""
        if robust and best["agree"] < len(shares):
            bad = [i for i in range(len(shares)) if i not in best["agree_idx"]]
            note = f"отброшены несогласованные доли: {bad}"
        same_secret = [c for c in candidates if c["secret"] == secret]
        if len(same_secret) > 1 and not note:
            note = ("поле не определено: подходит несколько, но секрет от поля "
                    "не зависит")
        if rational is not None:
            note = note or "рациональная интерполяция совпала с модульной"
        return dict(shares=len(shares), k=k, prime=chosen, secret=secret,
                    consistent=True, bad_shares=[], note=note,
                    candidates=_public(candidates))

    if rational is not None and rational > 0 and rational.bit_length() <= 8192:
        return dict(shares=len(shares), k=k, prime=None, secret=rational,
                    consistent=True, bad_shares=[],
                    note="рациональная интерполяция (секрет меньше поля)",
                    candidates=_public(candidates))

    if prime and candidates:
        return dict(shares=len(shares), k=k, prime=prime,
                    secret=candidates[0]["secret"], consistent=True,
                    bad_shares=[], note="",
                    candidates=_public(candidates))

    raise ValueError(
        "долей ровно столько, сколько нужно: модуль не определить. "
        "Укажи --prime или дай лишние доли")


def _public(cands):
    return [{"prime": str(c["prime"]), "secret": str(c["secret"]),
             "agree": c["agree"]} for c in cands[:3]]


def solve_crt(pairs):
    """(m, r) → x mod M и кандидаты."""
    x, M = 0, 1
    for m, r in pairs:
        if m <= 0:
            raise ValueError(f"модуль должен быть положительным: {m}")
        g = _gcd(M, m)
        if (r - x) % g:
            raise ValueError(f"остатки несовместимы: {m}, {r}")
        m1, m2 = M // g, m // g
        t = ((r - x) // g * pow(m1 % m2, -1, m2)) % m2 if m2 > 1 else 0
        new_M = M * m // g
        x = (x + M * t) % new_M
        M = new_M
    return x, M


def _gcd(a, b):
    while b:
        a, b = b, a % b
    return a


def main():
    ap = argparse.ArgumentParser(
        prog="shamir.py", description="доли Шамира и CRT-остатки")
    ap.add_argument("--share", action="append", default=[], metavar="X:Y",
                    help="доля (можно несколько раз)")
    ap.add_argument("--file", help="файл с долями (по две числа в строке)")
    ap.add_argument("--prime", help="модуль поля (по умолчанию — подбор)")
    ap.add_argument("--k", type=int, help="сколько долей нужно (порог схемы)")
    ap.add_argument("--robust", action="store_true",
                    help="отбросить несогласованные доли и взять согласованные")
    ap.add_argument("--crt", action="store_true", help="режим CRT-остатков")
    ap.add_argument("--mod", action="append", default=[], metavar="M:R",
                    help="остаток r по модулю m (можно несколько раз)")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    if args.crt:
        if not args.mod:
            ap.error("для --crt нужен хотя бы один --mod 'm:r'")
        try:
            pairs = [parse_shares([x])[0] for x in args.mod]
        except ValueError as exc:
            print(f"[-] {exc}")
            sys.exit(2)
        try:
            x, M = solve_crt(pairs)
        except ValueError as exc:
            print(f"[-] {exc}")
            sys.exit(2)
        cands = []
        for shift in range(0, 4):
            val = x + shift * M
            cands.append((shift, val))
        payload = dict(moduli=[m for m, _ in pairs], solution=x, modulus=M,
                       candidates=[{"k": k, "value": v, "hex": hex(v),
                                    "ascii": describe(v)[1]} for k, v in cands])
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
            return
        print(f"[+] модулей: {len(pairs)}, M = {M} ({M.bit_length()} бит)")
        print(f"[+] x = {x}")
        for k, v in cands:
            hx, text = describe(v)
            print(f"    +{k}*M = {v}  {hx}" + (f"  {text!r}" if text else ""))
            for flag in common.find_flags(as_bytes(v)):
                print("[!!!] ФЛАГ:", flag)
        return

    pairs = parse_shares(args.share)
    if args.file:
        try:
            pairs += parse_shares_from_text(open(args.file, encoding="utf-8").read())
        except OSError as exc:
            print(f"[-] не открыть файл: {exc}")
            sys.exit(2)
    if len(pairs) < 2:
        ap.error("нужно хотя бы две доли: --share '1:y' --share '2:y' (или --file)")

    prime = _num(args.prime) if args.prime else None
    try:
        res = solve_shamir(pairs, prime=prime, k=args.k, robust=args.robust)
    except ValueError as exc:
        print(f"[-] {exc}")
        sys.exit(1)

    secret = res["secret"]
    hex_val, text = describe(secret)
    res["hex"] = hex_val
    res["ascii"] = text
    res["flags"] = common.find_flags(as_bytes(secret))

    if args.json:
        print(json.dumps(res, ensure_ascii=False, indent=2))
        return

    print(f"[+] долей: {res['shares']}, порог k={res['k']}")
    if res["prime"]:
        print(f"[+] поле: {res['prime']} ({res['prime'].bit_length()} бит)")
    if res["note"]:
        print(f"[i] {res['note']}")
    print(f"[+] секрет: {secret}  {hex_val}")
    if text:
        print(f"    как текст: {text!r}")
    if res["consistent"]:
        print("[+] остальные доли сходятся — набор верный")
    else:
        print(f"[!] доли не сходятся: {res['bad_shares']} — попробуй --robust "
              "или проверь поле")
    for flag in res["flags"]:
        print("[!!!] ФЛАГ:", flag)


if __name__ == "__main__":
    try:
        main()
    except BrokenPipeError:
        sys.exit(0)
