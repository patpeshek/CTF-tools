#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
xor_scan.py — найти XOR-ключ по файлу.

  python xor_scan.py bin
  python xor_scan.py bin --keylen 8
  python xor_scan.py bin --known "This is" --keylen 5
  python xor_scan.py bin --known "CTF{"            # длина ключа подбирается сама
  python xor_scan.py enc.bin --offset 1024 --length 4096

Режимы:
  * одиночный байт: перебор 1..255 по печатности и частым словам;
  * префиксы флагов (ctf{, flag{, …) как known plaintext — ключ любой длины
    меньше префикса, флаг может быть в середине файла;
  * повторяющийся ключ: для каждой позиции выбирается байт, дающий самый
    «текстовый» результат (буквы/пробел, а не просто печатные);
  * known plaintext: ключ восстанавливается точно, текст ищется по всему файлу,
    ключ выравнивается к началу файла.
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

COMMON =[b"the", b"and", b"flag", b"ctf", b"this", b"key", b"secret", b"password"]


def printable_ratio(b: bytes) -> float:
    if not b:
        return 0.0
    return sum(32 <= c < 127 or c in (9, 10, 13) for c in b) / len(b)


def score(b: bytes) -> float:
    low = b.lower()
    words = sum(low.count(w) for w in COMMON)
    return printable_ratio(b) + words * 0.05


def single_byte(data: bytes, top=10):
    res = []
    for k in range(1, 256):
        dec = bytes(c ^ k for c in data)
        res.append((score(dec), k, dec))
    res.sort(key=lambda x: -x[0])
    return res[:top]


FREQ = b" etaoinshrdlu"


def text_score(b: bytes) -> float:
    """Похожесть на текст: при равной печатности выигрывают буквы/пробел, а не
    первый попавшийся байт (иначе для коротких колонок ключ угадывался неверно)."""
    if not b:
        return 0.0
    s = 0.0
    for c in b:
        if c in FREQ or (65 <= c <= 90 and c + 32 in FREQ):
            s += 3
        elif 65 <= c <= 90 or 97 <= c <= 122:
            s += 2
        elif 48 <= c <= 57 or c in b"_{}-.,:!'\"\n":
            s += 1
        elif not (32 <= c < 127 or c in (9, 13)):
            s -= 6
    return s / len(b)


def repeating(data: bytes, keylen: int):
    key = bytearray()
    for i in range(keylen):
        col = data[i::keylen][:4096]
        best_k, best_s = 0, None
        for k in range(256):
            s = text_score(bytes(c ^ k for c in col))
            if best_s is None or s > best_s:
                best_s, best_k = s, k
        key.append(best_k)
    dec = bytes(c ^ key[i % keylen] for i, c in enumerate(data))
    return bytes(key), dec


def xor_bytes(a: bytes, b: bytes) -> bytes:
    """a ^ b одинаковой длины через длинное целое (быстро на мегабайтах)."""
    n = len(a)
    return (int.from_bytes(a, "big") ^ int.from_bytes(b, "big")).to_bytes(n, "big")


def xor_key(data: bytes, key: bytes) -> bytes:
    stream = (key * (len(data) // len(key) + 1))[:len(data)]
    return xor_bytes(data, stream)


LIMIT = 4_000_000  # known plaintext ищется в первых 4 МБ


def known_search(data: bytes, known: bytes, keylens, diffs=None, need_text=False):
    """Known plaintext в любом месте файла. Для каждой длины ключа L < len(known)
    совпадение проверяется условием data[o+j]^data[o+j+L] == known[j]^known[j+L]
    (поиск через bytes.find), ключ выравнивается к началу файла.
    diffs — кэш {L: data[:-L]^data[L:]} для тех же data; need_text — за known
    должен идти печатный текст (префикс флага).
    Возвращает [(score, keylen, offset, key, dec)] по убыванию score."""
    data = data[:LIMIT]
    diffs = {} if diffs is None else diffs
    out = {}
    n = len(known)
    for L in keylens:
        if L < 1 or L > n or len(data) < n:
            continue
        if L == n:  # ключ из одного вхождения не проверить — только начало файла
            offsets = [0]
        else:
            if L not in diffs:
                diffs[L] = xor_bytes(data[:-L], data[L:])
            diff = diffs[L]
            pat = bytes(known[j] ^ known[j + L] for j in range(n - L))
            offsets, o = [], diff.find(pat)
            while o != -1 and len(offsets) < 50_000:
                if o + n <= len(data):
                    offsets.append(o)
                o = diff.find(pat, o + 1)
        for o in offsets:
            key = bytearray(L)
            for j in range(L):
                key[(o + j) % L] = data[o + j] ^ known[j]
            key = bytes(key)
            tail = data[o + n:o + n + 24]
            if need_text and tail and printable_ratio(
                    bytes(c ^ key[(o + n + i) % L] for i, c in enumerate(tail))) < 0.9:
                continue  # быстрый отсев: за префиксом флага идёт печатное
            start = max(0, o - 64)
            dec_w = bytes(c ^ key[(start + i) % L] for i, c in enumerate(data[start:o + 192]))
            run = 0  # сколько печатных подряд с позиции known (настоящий текст длиннее)
            for c in dec_w[o - start:o - start + 64]:
                if not (32 <= c < 127 or c in (9, 10, 13)):
                    break
                run += 1
            sc = printable_ratio(dec_w) + text_score(dec_w) / 10 + run / 64 - L * 0.01
            if o == 0:
                sc += 0.2  # заголовок файла — самый частый known plaintext
            if common.find_flags(dec_w):
                sc += 1.0
            if key not in out or sc > out[key][0]:
                out[key] = (sc, L, o, key)
    res = sorted(out.values(), key=lambda r: -r[0])
    return [(sc, L, o, key, xor_key(data, key)) for sc, L, o, key in res[:5]]


STRICT_FLAG = re.compile(r"[A-Za-z0-9_]+\{[A-Za-z0-9_\-!?.@#$%+=:]{3,}\}")


def strict_flags(b: bytes):
    """Флаги без «;», пробелов и т.п.: при автоматическом поиске неверный ключ
    иногда даёт правдоподобный мусор вида ctf{;ju;gv}, он не должен стать флагом."""
    return [f for f in common.find_flags(b) if STRICT_FLAG.fullmatch(f)
            and sum(c.isalnum() or c == "_" for c in f) / len(f) >= 0.8]


def flag_prefix_search(data: bytes, keylens):
    """Префиксы флагов (common.prefixes: ctf, flag, …) как known plaintext."""
    best = []
    data = data[:LIMIT]
    diffs = {}
    for pre in common.prefixes():
        for variant in sorted({pre, pre.upper(), pre.lower()}):
            known = (variant + "{").encode()
            lens = [L for L in keylens if L < len(known)]
            for r in known_search(data, known, lens, diffs, need_text=True):
                if strict_flags(r[4][r[2]:r[2] + 512]):
                    best.append((r[0], variant + "{", r))
    best.sort(key=lambda x: -x[0])
    return best


def show_known(label, r, flags_of=common.find_flags):
    sc, L, o, key, dec = r
    print(f"[+] known-plaintext {label} @0x{o:x}: keylen={L} key={key!r} hex={key.hex()}")
    start = max(0, o - 32)
    print(f"[+] text{f' @0x{start:x}' if start else ''}: {dec[start:start + 300]!r}")
    for f in flags_of(dec[o:o + 512]):
        print(f"[!!!] {f}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("file")
    ap.add_argument("--keylen", type=int)
    ap.add_argument("--known")
    ap.add_argument("--offset", type=int, default=0)
    ap.add_argument("--length", type=int, default=0)
    ap.add_argument("--top", type=int, default=10)
    ap.add_argument("--min-score", type=float, default=0.5)
    args = ap.parse_args()

    data = open(args.file, "rb").read()
    if args.offset or args.length:
        data = data[args.offset:args.offset + (args.length or None)]

    if args.known:
        # known plaintext в любом месте файла; без --keylen перебираются длины,
        # которые этот текст может подтвердить (1..len-1), и len — только с начала
        known = args.known.encode()
        lens = [args.keylen] if args.keylen else range(1, min(len(known), 64) + 1)
        res = known_search(data, known, lens)
        if res:
            show_known(repr(args.known), res[0])
        else:
            print("[-] known-текст не сходится ни с одной длиной ключа")
        return

    # префиксы флагов как known plaintext: многобайтовый ключ по «CTF{»
    hits = flag_prefix_search(data, [args.keylen] if args.keylen else range(1, 33))
    if hits:
        show_known(repr(hits[0][1]), hits[0][2], strict_flags)
        if args.keylen:
            return

    if args.keylen:
        key, dec = repeating(data, args.keylen)
        print(f"[+] key ({args.keylen}): {key!r}  hex={key.hex()}")
        print(f"[+] text: {dec[:400]!r}")
        return

    print("[+] одиночный байт, топ кандидатов:")
    for s, k, dec in single_byte(data, args.top):
        if s < args.min_score:
            continue
        print(f"  key=0x{k:02x} ({k:3d}) score={s:.2f}  {dec[:120]!r}")


if __name__ == "__main__":
    try:
        main()
    except (FileNotFoundError, IsADirectoryError, PermissionError) as e:
        print(f"[-] не могу открыть: {getattr(e, 'filename', None) or e}")
    except BrokenPipeError:
        pass
    except KeyboardInterrupt:
        print("\n[-] прервано")
