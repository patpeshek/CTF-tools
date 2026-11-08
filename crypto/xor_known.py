#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
xor_known.py — XOR с известным началом текста (known plaintext) и восстановление ключа.

Пример: ключ из 5 символов по маске [a-z][A-Z]\\S[0-9]\\d,
открытый текст начинается с "This is my message: ".

  python xor_known.py --hex 3139... --known "This is my message: " --keylen 5
  python xor_known.py --hex 3139... --known "This is my message: " --keylen 5 --regex "^[a-z][A-Z]\\S[0-9]\\d$"
  python xor_known.py --hex 3139... --key "aB!12"
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
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import common  # noqa: E402


def recover_key(cipher: bytes, known: bytes, keylen: int):
    key = bytearray(keylen)
    counts = [0] * keylen
    for i, p in enumerate(known):
        k = cipher[i] ^ p
        pos = i % keylen
        if counts[pos] == 0:
            key[pos] = k
            counts[pos] = 1
        elif key[pos] != k:
            return None
    for pos in range(keylen):
        if counts[pos] == 0:
            return None
    return bytes(key)


def printable_ratio(text: str) -> float:
    if not text:
        return 0.0
    ok = sum(1 for c in text if c.isprintable() or c in "\r\n\t")
    return ok / len(text)


def guess_keylen(data: bytes, known: bytes, limit: int = 32):
    """Перебирает длины ключа, при которых known-текст сходится, и ранжирует
    результат по читаемости расшифровки. Возвращает (score, keylen, key, text)."""
    out = []
    for klen in range(1, min(len(known), limit) + 1):
        key = recover_key(data, known, klen)
        if not key:
            continue
        text = xor(data, key).decode("utf-8", "replace")
        out.append((printable_ratio(text), -klen, klen, key, text))
    out.sort(reverse=True)
    return [(klen, key, text, score) for score, _, klen, key, text in out]


def xor(data: bytes, key: bytes) -> bytes:
    return bytes(c ^ key[i % len(key)] for i, c in enumerate(data))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("cipher", nargs="?", help="файл с шифротекстом (или --file)")
    ap.add_argument("--hex", help="шифротекст в hex")
    ap.add_argument("--file", help="файл с шифротекстом")
    ap.add_argument("--known", help="известное начало открытого текста")
    ap.add_argument("--keylen", type=int, help="длина ключа (если не указана — подбирается)")
    ap.add_argument("--key", help="готовый ключ")
    ap.add_argument("--regex", help="проверить ключ по регулярке")
    args = ap.parse_args()

    if args.hex:
        data = bytes.fromhex(args.hex)
    elif args.file or args.cipher:
        raw = open(args.file or args.cipher, "rb").read()
        try:
            data = bytes.fromhex(raw.decode().strip())
        except Exception:
            data = raw
    else:
        ap.error("нужен файл (позицией или --file) либо --hex")

    if args.key:
        key = args.key.encode()
    elif args.known:
        chosen = None  # (вариант, ключ, score)
        for kv in dict.fromkeys((args.known, args.known.upper(),
                                 args.known.lower(), args.known.capitalize())):
            known = kv.encode()
            if args.keylen:
                key = recover_key(data, known, args.keylen)
                if key:
                    chosen = (kv, key, 1.0)
                    break
                continue
            cands = guess_keylen(data, known)
            if cands and (chosen is None or cands[0][3] > chosen[2]):
                chosen = (kv, cands[0][1], cands[0][3])
        if not chosen:
            n = args.keylen or len(args.known)
            print(f"[-] known-текст не сходится (длины ключа 1..{n})")
            print("    проверь: тот ли это текст, нет ли сдвига/префикса перед ним")
            return
        variant, key, _ = chosen
        if variant != args.known:
            print(f"[i] известный текст сходится в регистре {variant!r}")
        if args.regex and not re.match(args.regex, key.decode("latin-1")):
            print("[!] ключ не подходит под regex (но попробуем расшифровать)")
        print(f"[+] ключ: {key!r}")
    else:
        ap.error("нужен --key ИЛИ --known")

    plain = xor(data, key)
    text = plain.decode("utf-8", "replace")
    print("\n[+] расшифровка:")
    print(text[:1000])
    cut = text.find("}")
    if cut != -1:
        print("\n[+] до '}':", text[:cut + 1])
    for f in common.find_flags(plain[:100000]):
        print("[!!!] ФЛАГ:", f)


if __name__ == "__main__":
    try:
        main()
    except (FileNotFoundError, IsADirectoryError, PermissionError) as e:
        print(f"[-] не могу открыть: {getattr(e, 'filename', None) or e}")
    except BrokenPipeError:
        pass
    except KeyboardInterrupt:
        print("\n[-] прервано")
