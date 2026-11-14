#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
otp_reuse.py — два шифротекста с одинаковым потоком (two-time pad).

  python otp_reuse.py --c1 <hex> --c2 <hex>
  python otp_reuse.py --c1 ... --c2 ... --crib "the "
  python otp_reuse.py --c1 ... --c2 ... --crib "flag{" --min-printable 0.8

Разбор реального лога перехвата (nonce + c1/c2 в base64):

  python otp_reuse.py --log traffic.log --crib-file known.txt
  python otp_reuse.py --log traffic.log --crib "Quarterly report"

Работает, когда один и тот же keystream использован дважды:
    c1 ^ c2 = p1 ^ p2
Дальше подставляем известное слово (crib) в p1 и смотрим, получается ли
осмысленный p2 на этом месте. В режиме --log p2 = c1 ^ c2 ^ p1 сразу даёт
открытый текст второго сообщения (и, как правило, флаг).
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
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import common  # noqa: E402


def printable_ratio(b: bytes) -> float:
    if not b:
        return 0.0
    return sum(32 <= c < 127 or c in (9, 10, 13) for c in b) / len(b)


def xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def xor3(a: bytes, b: bytes, c: bytes) -> bytes:
    return bytes(x ^ y ^ z for x, y, z in zip(a, b, c))


# --- разбор лога перехвата -------------------------------------------------

_NONCE_RE = re.compile(r"\bnonce\s*=\s*([0-9a-fA-F]+)")
_FIELD_RE = re.compile(r"\b(c1|c2)\s*=\s*([A-Za-z0-9+/=]+)", re.IGNORECASE)
_FLAG_FALLBACK_RE = re.compile(
    r"\b([A-Za-z][A-Za-z0-9_]{1,31})\{([^{}\x00-\x1f]{1,300})\}")


def parse_log(text: str) -> "dict[str, dict[str, str | None]]":
    """Собирает из лога пары nonce -> {c1, c2}.

    nonce и c1/c2 могут лежать на разных строках; регистр c1=/c2= не важен.
    Возвращает dict: nonce (hex, lowercase) -> {"c1": b64, "c2": b64}.
    """
    sessions: dict[str, dict[str, str | None]] = {}
    current: str | None = None
    for line in text.splitlines():
        m = _NONCE_RE.search(line)
        if m:
            current = m.group(1).lower()
            sessions.setdefault(current, {"c1": None, "c2": None})
        for mm in _FIELD_RE.finditer(line):
            if current is None:
                current = "<none>"
            s = sessions.setdefault(current, {"c1": None, "c2": None})
            s[mm.group(1).lower()] = mm.group(2).strip()
    return sessions


def b64decode(s: str) -> bytes:
    """Декодирует base64, сам доставляя недостающий padding. Ясная ошибка."""
    s = s.strip()
    pad = (-len(s)) % 4
    try:
        return base64.b64decode(s + "=" * pad, validate=False)
    except Exception as e:
        raise ValueError(
            f"не получается декодировать base64 ({s[:40]}{'...' if len(s) > 40 else ''}): {e}"
        ) from e


def _read_crib(args) -> bytes | None:
    if args.crib_file:
        try:
            data = open(args.crib_file, "rb").read()
        except OSError as e:
            print(f"[-] не могу открыть --crib-file: {e}")
            raise SystemExit(2) from e
        return data.strip()
    if args.crib:
        return args.crib.encode()
    return None


def _show_flags(p2: bytes, text: str) -> None:
    """Печатает флаги: сначала common.find_flags, затем любой {…}-хвост."""
    flags = common.find_flags(p2[:100000])
    seen = set(flags)
    for f in flags:
        print("[!!!] ФЛАГ:", f)
    for m in _FLAG_FALLBACK_RE.finditer(text):
        cand = m.group(0)
        if cand not in seen:
            print("[+] похоже на флаг (префикс не из набора):", cand)


def run_log_mode(args) -> None:
    try:
        raw = open(args.log, "r", encoding="utf-8", errors="replace").read()
    except OSError as e:
        print(f"[-] не могу открыть лог: {e}")
        raise SystemExit(2) from e

    sessions = parse_log(raw)
    if not sessions:
        print("[-] в логе не найдено nonce=/c1=/c2=")
        return

    crib = _read_crib(args)
    if not crib:
        print("[-] нужен crib: --crib \"текст\" или --crib-file файл")
        return

    pairs = []
    for nonce, fields in sessions.items():
        if fields["c1"] is None or fields["c2"] is None:
            continue
        pairs.append((nonce, fields["c1"], fields["c2"]))

    if not pairs:
        print("[-] нет ни одной пары c1+c2 с одним nonce в логе")
        for nonce, fields in sessions.items():
            print(f"    nonce {nonce}: c1={'есть' if fields['c1'] else 'нет'}, "
                  f"c2={'есть' if fields['c2'] else 'нет'}")
        return

    results = []
    for nonce, c1_b64, c2_b64 in pairs:
        try:
            c1 = b64decode(c1_b64)
            c2 = b64decode(c2_b64)
        except ValueError as e:
            print(f"[!] nonce {nonce}: {e}")
            continue

        print(f"\n=== nonce {nonce} ===")
        print(f"[+] c1: {len(c1)} байт, c2: {len(c2)} байт, crib: {len(crib)} байт")

        n = min(len(c1), len(c2), len(crib))
        if n == 0:
            print("[-] пустой ввод")
            continue
        if len(crib) > n:
            print(f"[i] crib длиннее c2: беру первые {n} байт")
        elif len(c2) > n:
            print(f"[i] c2 длиннее crib: восстанавливаю только первые {n} байт")

        # two-time pad: c1 ^ c2 = p1 ^ p2  =>  p2 = c1 ^ c2 ^ p1
        p2 = xor3(c1[:n], c2[:n], crib[:n])
        text = p2.decode("utf-8", "replace")
        print("[+] расшифровка c2 (p2 = c1^c2^p1):")
        print(text)
        _show_flags(p2, text)
        results.append((nonce, printable_ratio(p2)))

    if len(results) > 1:
        print("\n[+] итог по nonce:")
        for nonce, ratio in results:
            mark = "совпал" if ratio >= args.min_printable else "не совпал"
            print(f"    {nonce}: {mark} (печатных {ratio:.0%})")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--c1", help="hex или файл с hex (первый шифротекст)")
    ap.add_argument("--c2", help="hex или файл с hex (второй шифротекст)")
    ap.add_argument("--crib", help="известный кусок открытого текста")
    ap.add_argument("--crib-file", help="файл с известным открытым текстом")
    ap.add_argument("--log", help="лог перехвата: nonce=… и c1=/c2= (base64)")
    ap.add_argument("--min-printable", type=float, default=0.75)
    args = ap.parse_args()

    if args.log:
        run_log_mode(args)
        return

    if not (args.c1 and args.c2):
        ap.error("нужны --c1 и --c2 (или --log с --crib/--crib-file)")

    def load(s):
        try:
            return bytes.fromhex(re.sub(r"(?i)0x|[\s:]", "", s))
        except ValueError:
            return bytes.fromhex(re.sub(r"(?i)0x|[\s:]", "", open(s).read()))

    c1, c2 = load(args.c1), load(args.c2)
    n = min(len(c1), len(c2))
    x = xor(c1[:n], c2[:n])
    print(f"[+] длина: {n}")
    print("[+] c1^c2 (печатное):")
    print("".join(chr(c) if 32 <= c < 127 else "." for c in x))

    crib = _read_crib(args)
    if not crib:
        return
    print(f"\n[+] ищу crib {crib!r}:")
    found = 0
    for i in range(0, n - len(crib) + 1):
        p2 = xor(x[i:i + len(crib)], crib)
        if printable_ratio(p2) >= args.min_printable:
            found += 1
            ctx_lo = max(0, i - 20)
            ctx_hi = min(n, i + len(crib) + 20)
            print(f"  pos={i}: p1={crib!r}  p2={p2!r}")
            print(f"        контекст p1^p2: "
                  f"{''.join(chr(c) if 32 <= c < 127 else '.' for c in x[ctx_lo:ctx_hi])}")
    if not found:
        print("  [-] совпадений нет; попробуй другой crib или проверь, что поток общий")


if __name__ == "__main__":
    try:
        main()
    except (FileNotFoundError, IsADirectoryError, PermissionError) as e:
        print(f"[-] не могу открыть: {getattr(e, 'filename', None) or e}")
    except BrokenPipeError:
        pass
    except KeyboardInterrupt:
        print("\n[-] прервано")
