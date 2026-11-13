#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
whitespace.py — Whitespace, невидимые символы и «пробельные» кодировки.

  python whitespace.py file.txt
  python whitespace.py file.txt --mode ws
  python whitespace.py file.txt --mode bits
  python whitespace.py file.txt --mode zw
  python whitespace.py file.txt --mode trail
  python whitespace.py file.txt --mode auto

Режимы:
  ws      — интерпретатор Whitespace (space/tab/LF)
  bits    — space=0, tab=1 → байты (поток и по строкам)
  zw      — zero-width символы (ZWSP/ZWNJ/ZWJ/…)
  vs      — variation selectors U+FE00..FE0F (4 бита)
  tags    — Unicode tag characters U+E0000..E007F (ASCII smuggling)
  braille — U+2800..U+28FF → байт
  trail   — хвостовые пробелы/табы в строках → биты
  auto    — определить по содержимому
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

S, T, L = " ", "\t", "\n"


# ---------------- Whitespace interpreter ----------------
#
# Спецификация (IMP — префикс группы команд):
#   [Space]       стек:  S n push, LS dup, TS n copy, LT swap, LL discard, TL n slide
#   [Tab][Space]  арифметика: SS add, ST sub, SL mul, TS div, TT mod
#   [Tab][Tab]    куча:  S store, T retrieve
#   [LF]          поток: SS l mark, ST l call, SL l jump, TS l jz, TT l jn, TL ret, LL end
#   [Tab][LF]     ввод/вывод: SS outchar, ST outnum, TS readchar, TT readnum
# Число: знак (S=+, T=-), затем биты (S=0, T=1) до LF.
# Метка: биты до LF; сравнивается как строка («S» и «SS» — разные метки).

_WS_CMDS = {
    S: {S: "push", T + S: "copy", T + L: "slide",
        L + S: "dup", L + T: "swap", L + L: "discard"},
    T + S: {S + S: "add", S + T: "sub", S + L: "mul", T + S: "div", T + T: "mod"},
    T + T: {S: "store", T: "retrieve"},
    L: {S + S: "label", S + T: "call", S + L: "jump", T + S: "jz", T + T: "jn",
        T + L: "ret", L + L: "end"},
    T + L: {S + S: "outchar", S + T: "outnum", T + S: "readchar", T + T: "readnum"},
}
_WS_NUM_ARG = {"push", "copy", "slide"}
_WS_LABEL_ARG = {"label", "call", "jump", "jz", "jn"}


def tokenize(prog: str):
    code = [c for c in prog if c in (S, T, L)]
    n = len(code)
    i = 0
    out = []

    def rd():
        nonlocal i
        if i >= n:
            raise ValueError("программа оборвалась посреди команды")
        c = code[i]
        i += 1
        return c

    def bits_until_lf():
        s = []
        while True:
            c = rd()
            if c == L:
                return "".join(s)
            s.append("1" if c == T else "0")

    def num():
        c = rd()
        if c == L:                       # без знака и битов — 0
            return 0
        sign = -1 if c == T else 1
        b = bits_until_lf()
        return sign * int(b, 2) if b else 0

    while i < n:
        imp = rd()
        if imp == T:
            imp += rd()
        table = _WS_CMDS[imp]
        cmd = rd()
        if cmd not in table:
            cmd += rd()
        op = table.get(cmd)
        if op is None:
            raise ValueError(f"неизвестная команда {imp + cmd!r} на позиции {i}")
        if op in _WS_NUM_ARG:
            out.append((op, num()))
        elif op in _WS_LABEL_ARG:
            out.append((op, bits_until_lf()))
        else:
            out.append((op, None))
    return out


def run_ws(prog: str, inp: str = "", max_steps: int = 5_000_000):
    ops = tokenize(prog)
    labels = {}
    for idx, (op, arg) in enumerate(ops):
        if op == "label":
            labels.setdefault(arg, idx)
    stack, heap, calls = [], {}, []
    pc, out, steps = 0, [], 0
    inp_pos = 0

    def pop():
        if not stack:
            raise ValueError(f"стек пуст (команда {pc - 1}: {ops[pc - 1][0]})")
        return stack.pop()

    def goto(label):
        if label not in labels:
            raise ValueError(f"нет метки {label!r}")
        return labels[label]

    while pc < len(ops) and steps < max_steps:
        steps += 1
        op, arg = ops[pc]
        pc += 1
        if op == "push":
            stack.append(arg)
        elif op == "dup":
            v = pop()
            stack += [v, v]
        elif op == "copy":
            if not 0 <= arg < len(stack):
                raise ValueError(f"copy {arg}: в стеке {len(stack)}")
            stack.append(stack[-1 - arg])
        elif op == "swap":
            b, a = pop(), pop()
            stack += [b, a]
        elif op == "discard":
            pop()
        elif op == "slide":
            top = pop()
            if arg > 0:
                del stack[-arg:]
            stack.append(top)
        elif op in ("add", "sub", "mul", "div", "mod"):
            b, a = pop(), pop()
            if op == "add":
                stack.append(a + b)
            elif op == "sub":
                stack.append(a - b)
            elif op == "mul":
                stack.append(a * b)
            elif b == 0:
                raise ValueError("деление на 0")
            else:                        # как div/mod в Haskell: к -бесконечности
                stack.append(a // b if op == "div" else a % b)
        elif op == "store":
            v, addr = pop(), pop()
            heap[addr] = v
        elif op == "retrieve":
            stack.append(heap.get(pop(), 0))
        elif op == "outchar":
            v = pop()
            out.append(chr(v) if 0 <= v < 0x110000 else chr(v & 0xFF))
        elif op == "outnum":
            out.append(str(pop()))
        elif op == "readchar":
            addr = pop()
            if inp_pos < len(inp):
                heap[addr] = ord(inp[inp_pos])
                inp_pos += 1
            else:
                heap[addr] = -1          # EOF
        elif op == "readnum":
            addr = pop()
            end = inp.find("\n", inp_pos)
            end = len(inp) if end == -1 else end
            try:
                heap[addr] = int(inp[inp_pos:end].strip() or "0")
            except ValueError:
                heap[addr] = 0
            inp_pos = end + 1
        elif op == "label":
            pass
        elif op == "call":
            calls.append(pc)
            pc = goto(arg)
        elif op == "jump":
            pc = goto(arg)
        elif op == "jz":
            if pop() == 0:
                pc = goto(arg)
        elif op == "jn":
            if pop() < 0:
                pc = goto(arg)
        elif op == "ret":
            if not calls:
                raise ValueError("ret без call")
            pc = calls.pop()
        elif op == "end":
            break
    return "".join(out), steps


# ---------------- прочие пробельные кодировки ----------------

def bits_to_bytes(bits: str):
    bits = "".join(c for c in bits if c in "01")
    out = bytearray()
    for i in range(0, len(bits) - 7, 8):
        out.append(int(bits[i:i + 8], 2))
    return bytes(out)


def decode_bits(text: str):
    res = []
    stream = "".join("1" if c == T else "0" if c == S else "" for c in text)
    if stream:
        res.append(("поток space/tab", bits_to_bytes(stream)))
    per_line = []
    for line in text.splitlines():
        b = "".join("1" if c == T else "0" if c == S else "" for c in line)
        if b:
            per_line.append(bits_to_bytes(b))
    if per_line and all(per_line):
        res.append(("по строкам", b"".join(per_line)))
    return res


ZW = {"\u200b": "0", "\u200c": "1", "\u200d": " ", "\u2060": "", "\ufeff": ""}


def decode_zero_width(text: str):
    chars = [c for c in text if c in ZW]
    res = []
    for a, b in (("\u200b", "\u200c"), ("\u200c", "\u200b"),
                 ("\u200b", "\u200d"), ("\u200d", "\u200b")):
        bits = "".join("1" if c == b else "0" if c == a else "" for c in chars)
        res.append((f"zw {ord(a):04x}=0 {ord(b):04x}=1", bits_to_bytes(bits)))
    return res


def decode_variation(text: str):
    vals = [ord(c) - 0xFE00 for c in text if 0xFE00 <= ord(c) <= 0xFE0F]
    bits = "".join(f"{v:04b}" for v in vals)
    return [("variation selectors", bits_to_bytes(bits))]


def decode_tags(text: str):
    chars = [chr(ord(c) - 0xE0000) for c in text if 0xE0000 <= ord(c) <= 0xE007F]
    return [("unicode tags", "".join(chars).encode("utf-8", "replace"))]


def decode_braille(text: str):
    vals = [ord(c) - 0x2800 for c in text if 0x2800 <= ord(c) <= 0x28FF]
    return [("braille", bytes(vals))]


def decode_trailing(text: str):
    bits = []
    for line in text.splitlines():
        trail = line[len(line.rstrip(" \t")):]
        for c in trail:
            bits.append("1" if c == "\t" else "0")
    return [("хвостовые пробелы", bits_to_bytes("".join(bits)))]


# ---------------- перебор схем ----------------
#
# Один и тот же файл прячут по-разному: таб=1/пробел=0 и наоборот, читают
# по строкам или единым потоком, берут 5/6/7/8 бит, сдвигают начало, читают
# с конца строки, пишут длину «хвоста» или длину серии пробелов. Раньше
# скрипт угадывал один вариант — если он не тот, получался мусор. brute
# прогоняет все разумные варианты и сортирует по «похожести на текст».

_TRIGRAMS = ("the", "and", "ing", "ion", "ent", "her", "tha", "flag", "key", "ctf")
_COMMON_WORDS = {"the", "and", "is", "are", "to", "of", "in", "that", "for",
                 "with", "you", "your", "key", "flag", "ctf", "secret", "this",
                 "was", "not", "have", "from", "it", "on", "at", "as", "be",
                 "or", "my", "we", "do", "if", "so", "no", "here", "there"}


def text_score(data: bytes) -> float:
    """Насколько результат похож на настоящий текст (и на флаг)."""
    if not data:
        return -1.0
    printable = sum(32 <= c < 127 or c in (9, 10, 13) for c in data) / len(data)
    low = data.decode("latin-1").lower()
    tri = sum(low.count(t) for t in _TRIGRAMS)
    letters = sum(c.isalpha() for c in low) / len(low)
    words = re.findall(r"[a-z0-9_]{2,}", low)
    hits = sum(1 for w in words if w in _COMMON_WORDS)
    sc = printable * 10 + min(tri, 20) * 1.5 + letters * 4 + hits * 3
    if re.search(r"[A-Za-z]{3,}", low):
        sc += 2
    try:
        if common.find_flags(data):
            sc += 40
        else:
            # «текст» без единого пробела — почти всегда мусор из битов
            if len(data) > 10 and b" " not in data:
                sc -= 5
            if "{" in low and "}" in low:
                sc += 2
    except Exception:
        pass
    if len(set(data)) <= 2:
        sc -= 10
    return sc


def _bit_stream(chunk: str, space_is_zero: bool) -> str:
    return "".join("0" if c == " " else "1" for c in chunk) if space_is_zero \
        else "".join("1" if c == " " else "0" for c in chunk)


def _pack(bits: str, width: int, offset: int, lsb: bool) -> bytes:
    out = bytearray()
    for i in range(offset, len(bits) - width + 1, width):
        chunk = bits[i:i + width]
        if lsb:
            chunk = chunk[::-1]
        v = int(chunk, 2)
        if v < 256:
            out.append(v)
    return bytes(out)


def _extra_families(bits: str):
    """Нестандартные упаковки битов: 7+чётность, повтор×3, 6 бит, цифры 0..7."""
    out = []
    # 7 бит данных + 1 бит чётности на каждые 8 символов
    for parity_at in (7, 0):
        kept = "".join(b for i, b in enumerate(bits) if i % 8 != parity_at)
        for offset in range(4):
            for lsb in (False, True):
                out.append((f"7 бит + чётность (выброшен бит {parity_at}), "
                            f"сдвиг {offset}{', LSB' if lsb else ''}",
                            _pack(kept, 7, offset, lsb)))
    # каждый бит повторён трижды — берём большинство
    if len(bits) >= 30:
        voted = "".join("1" if g.count("1") > 1 else "0"
                        for g in (bits[i:i + 3] for i in range(0, len(bits) - 2, 3)))
        for offset in range(3):
            out.append((f"повтор×3, сдвиг {offset}", _pack(voted, 8, offset, False)))
    # 6 бит на символ (base64-алфавит → латиница/цифры)
    b64 = ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")
    for offset in range(6):
        chars = [b64[int(bits[i:i + 6], 2)]
                 for i in range(offset, len(bits) - 5, 6)]
        out.append((f"6 бит, сдвиг {offset}", "".join(chars).encode()))
    return out


def brute_candidates(text: str, limit: int = 6):
    """Все разумные пробельные схемы → лучшие кандидаты [(score, name, bytes)]."""
    lines = text.splitlines()
    trails = [ln[len(ln.rstrip(" \t\r")):] for ln in lines]
    trails = [t for t in trails if t]
    ws_all = "".join(c for c in text if c in " \t")

    sources = []
    if trails:
        sources.append(("хвосты строк", trails))
    if ws_all:
        sources.append(("все пробелы/табы", [ws_all]))

    found = []

    def add(name, data):
        if len(data) >= 3:
            found.append((text_score(data), name, data))

    for sname, chunks in sources:
        for space_is_zero in (True, False):
            raw = [_bit_stream(c, space_is_zero) for c in chunks]
            for direction in ("вперёд", "реверс строк", "реверс потока"):
                parts = [b[::-1] if direction == "реверс строк" else b for b in raw]
                if direction == "реверс потока":
                    parts = ["".join(parts)[::-1]]
                joined = "".join(parts)
                for name, data in _extra_families(joined):
                    add(f"{sname}, {'таб=1' if space_is_zero else 'пробел=1'}, "
                        f"{direction}, {name}", data)
                for per_line in (False, True):
                    units = parts if per_line else [joined]
                    for width in (8, 7, 6, 5):
                        for offset in range(width):
                            for lsb in (False, True):
                                data = b"".join(
                                    _pack(u, width, offset, lsb) for u in units)
                                add(f"{sname}, таб=1, {direction}, "
                                    f"{'по строкам' if per_line else 'потоком'}, "
                                    f"{width} бит, сдвиг {offset}"
                                    f"{', LSB' if lsb else ''}", data)

    # своя полярность у каждой строки (генератор мог писать случайно)
    if 1 < len(trails) <= 12:
        base = [_bit_stream(t, True) for t in trails]
        for mask in range(1 << len(trails)):
            bits = "".join(b.translate(str.maketrans("01", "10")) if mask >> i & 1
                           else b for i, b in enumerate(base))
            for offset in (0, 4):
                add(f"хвосты строк, полярность по маске {mask:0{len(trails)}b}, "
                    f"8 бит, сдвиг {offset}", _pack(bits, 8, offset, False))

    # длина серии пробелов между табами как цифра (0..7) — база 8
    if trails:
        digits = [len(seg) for t in trails for seg in t.split("\t")]
        dstr = "".join(str(d) for d in digits)
        for width in (2, 3, 4):
            for offset in range(4):
                s = dstr[offset:]
                data = bytes(int(s[i:i + width], 8) & 0xFF
                             for i in range(0, len(s) - width + 1, width)
                             if int(s[i:i + width], 8) <= 0x10FFFF)
                add(f"серии пробелов как цифры, база 8, {width} цифры, "
                    f"сдвиг {offset}", data)

    # длина хвоста / число табов в строке как байты и как буквы
    if trails:
        lens = bytes(len(t) & 0xFF for t in trails)
        add("длина хвоста строки → байт", lens)
        add("длина хвоста → буква (mod 26)",
            bytes(97 + len(t) % 26 for t in trails))
        add("число табов в строке → байт",
            bytes(t.count("\t") & 0xFF for t in trails))

    # убрать повторы, оставить лучшее
    best = {}
    for sc, name, data in found:
        key = data
        if key not in best or sc > best[key][0]:
            best[key] = (sc, name, data)
    out = sorted(best.values(), key=lambda x: -x[0])
    return out[:limit]


def decode_snow(text: str, limit: int = 4000, password: str | None = None):
    """SNOW (stegsnow): 3 бита на серию пробелов, таб разделяет, таб в начале
    хвоста = начало данных.

    Формат из исходников stegsnow (encode.c: decode_bits/decode_whitespace/
    message_extract, compress.c: output_bit): хвостовой whitespace строки;
    пока не встретилась строка, чей хвост начинается с таба, данные не начались;
    затем каждая серия пробелов длины n (0..7) перед табом (и в конце хвоста)
    даёт 3 бита: n&1, (n>>1)&1, (n>>2)&1; биты собираются в байт MSB-first.
    """
    bits = []
    started = False
    lines_used = 0
    for line in text.splitlines():
        line = line.rstrip("\r")
        i = len(line)
        while i > 0 and line[i - 1] in " \t":
            i -= 1
        if i == len(line):
            continue
        tail = line[i:]
        if not started:
            if tail[0] == " ":
                continue
            started = True
            tail = tail[1:]
            if not tail:
                continue
        lines_used += 1

        def push(spc):
            bits.extend(((spc & 1), (spc >> 1) & 1, (spc >> 2) & 1))

        spc = 0
        for ch in tail:
            if ch == " ":
                spc += 1
            elif ch == "\t":
                push(spc)
                spc = 0
        if spc > 0:
            push(spc)

    if not bits:
        return None
    if password:
        import os as _os
        import sys as _sys
        try:
            import ice
        except ImportError:
            here = _os.path.dirname(_os.path.abspath(__file__))
            if here not in _sys.path:
                _sys.path.insert(0, here)
            import ice
        bits = ice.decrypt_bits(password, bits)
    out = bytearray()
    for i in range(0, len(bits) - 7, 8):
        v = 0
        for b in bits[i:i + 8]:
            v = (v << 1) | b
        out.append(v)
    return {"bits": len(bits), "lines": lines_used, "data": bytes(out)}


def run_snow(text: str, out_path: str | None = None,
             password: str | None = None):
    res = decode_snow(text, password=password)
    if not res:
        print("[-] SNOW-данных не видно (нет хвоста, начинающегося с таба)")
        return []
    data = res["data"]
    printable = sum(32 <= c < 127 or c in (9, 10, 13) for c in data) / max(1, len(data))
    print(f"\n[SNOW] строк с данными: {res['lines']}, бит: {res['bits']} "
          f"→ {len(data)} байт, printable={printable:.2f}"
          + (f", пароль: {password!r}" if password else ", без пароля"))
    print("  hex:", data.hex())
    print("  как текст:", repr(data.decode("utf-8", "replace")[:300]))
    magic = {b"\x1f\x8b": "gzip", b"BZh": "bzip2", b"PK": "zip", b"%PDF": "pdf",
             b"\x78\x9c": "zlib", b"\x78\x01": "zlib", b"\x78\xda": "zlib"}
    for m, name in magic.items():
        if data.startswith(m):
            print(f"  [!] похоже на {name}: попробуй распаковать")
            try:
                import zlib
                if name.startswith("zlib"):
                    print("  распаковано:", zlib.decompress(data)[:300])
            except Exception:
                pass
    if printable < 0.85:
        if password:
            print("  [!] с этим паролем не текст: пароль не тот или snow -C "
                  "(Huffman-сжатие)")
        else:
            print("  [!] данные не текст: похоже на snow с паролем (-p) — "
                  "попробуй --password ПАРОЛЬ; ещё вариант -C (сжатие)")
    flags = common.find_flags(data)
    for f in flags:
        print("  !!! ФЛАГ:", f)
    if out_path:
        with open(out_path, "wb") as fh:
            fh.write(data)
        print(f"  [+] байты сохранены: {out_path}")
    return flags


def run_brute(text: str, limit: int = 6):
    print("\n[перебор пробельных схем]")
    cands = brute_candidates(text, limit)
    if not cands:
        print("  [-] ничего не нашлось")
        return []
    flags = []
    for i, (sc, name, data) in enumerate(cands, 1):
        printable = sum(32 <= c < 127 or c in (9, 10, 13) for c in data) / max(1, len(data))
        print(f"\n  {i}. score={sc:5.1f} printable={printable:.2f}  {name}")
        print(f"     {data[:160]!r}")
        for f in common.find_flags(data):
            print(f"     !!! ФЛАГ: {f}")
            flags.append(f)
    return flags


def run_structure(text: str):
    """Структурный разбор хвостового whitespace: токены, гистограммы, энтропия.

    Нужен, когда биты «не читаются»: видно, похоже ли содержимое на случайный
    паддинг (тогда данные спрятаны иначе — в позициях, счётчиках, порядке).
    """
    lines = text.splitlines()
    rows = [ln[len(ln.rstrip(" \t\r")):] for ln in lines]
    rows = [r for r in rows if r]
    total = sum(len(r) for r in rows)
    spaces = sum(r.count(" ") for r in rows)
    tabs = sum(r.count("\t") for r in rows)
    print(f"\n[структура хвостов] строк с хвостами: {len(rows)}, "
          f"символов: {total} (пробелов {spaces}, табов {tabs})")
    print("   len | проб | таб | токены «k пробелов + таб»")
    for i, r in enumerate(rows):
        segs = [len(s) for s in r.split("\t")]
        print(f"  {len(r):4d} | {r.count(' '):4d} | {r.count(chr(9)):3d} | {segs}")

    digits = [len(s) for r in rows for s in r.split("\t")]
    hist = {k: digits.count(k) for k in range(max(digits) + 1)}
    print(f"\n[серии пробелов] n={len(digits)}, распределение: " +
          " ".join(f"{k}:{v}" for k, v in hist.items()))
    uniform = all(abs(v - len(digits) / len(hist)) <= 2.5 * (len(digits) / len(hist)) ** 0.5
                  for v in hist.values())
    print("  " + ("похоже на равномерный случайный паддинг — данные, скорее всего, "
                  "не в значениях серий" if uniform else
                  "распределение неровное — значения серий могут быть данными"))
    if total >= 8:
        print(f"\n[если это биты space/tab] {total} бит = {total // 8} байт + {total % 8} бит")
        print(f"  доля табов: {tabs / total:.2f} (для текста ждём ~0.35-0.5)")
    print("\n[подсказки, что делать дальше]")
    print("  - биты в порядке space/tab и сдвиги: --mode brute")
    print("  - данные в счётчиках/позициях: смотри колонки табов ниже")
    for i, r in enumerate(rows):
        pos = [j for j, c in enumerate(r) if c == "\t"]
        print(f"  строка {i}: табы на позициях {pos}")
    return


def rtf_report(path: str, password: str | None = None):
    """RTF: показать текст, структуру хвостов и прогнать перебор."""
    data = open(path, "rb").read()
    if not common.is_rtf(data):
        print("[-] это не RTF")
        return []
    text = common.rtf_to_text(data)
    print(f"\n[текст RTF] {len(text)} символов")
    print("  " + repr(text[:300]))
    raw = data.decode("latin-1")
    run_structure(raw)
    run_snow(raw, password=password)
    return run_brute(raw)


def report(name, data):
    text = data.decode("utf-8", "replace")
    flags = common.find_flags(data)
    printable = sum(32 <= c < 127 or c in (9, 10, 13) for c in data) / max(1, len(data))
    print(f"\n[{name}] {len(data)} b, printable={printable:.2f}")
    print("  text:", repr(text[:400]))
    print("  hex :", data[:96].hex())
    for f in flags:
        print("  !!! ФЛАГ:", f)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("file")
    ap.add_argument("--mode", default="auto",
                    choices=["auto", "ws", "bits", "zw", "vs", "tags", "braille",
                             "trail", "brute", "rtf", "report", "snow"])
    ap.add_argument("--input", default="", help="вход для whitespace read")
    ap.add_argument("--out", help="куда сохранить найденные байты (snow)")
    ap.add_argument("--password", help="пароль snow (-p): ICE-шифр на битах")
    ap.add_argument("--max-steps", type=int, default=5_000_000)
    common.add_flag_args(ap)
    args = ap.parse_args()
    common.apply_flag_args(args)

    raw_bytes = open(args.file, "rb").read()
    text = raw_bytes.decode("utf-8", "replace")
    mode = args.mode
    auto = mode == "auto"
    if auto:
        if any(0xFE00 <= ord(c) <= 0xFE0F for c in text):
            mode = "vs"
        elif any(0xE0000 <= ord(c) <= 0xE007F for c in text):
            mode = "tags"
        elif any(c in ZW for c in text):
            mode = "zw"
        elif any(0x2800 <= ord(c) <= 0x28FF for c in text):
            mode = "braille"
        elif all(c in (S, T, L, "\r") for c in text):
            # раньше trail: у программы из одних пробелов «хвост» в каждой строке
            mode = "ws"
        elif common.is_rtf(raw_bytes):
            mode = "rtf"
        elif any(line != line.rstrip(" \t") for line in text.splitlines()):
            mode = "trail"
        else:
            mode = "bits"
        print(f"[i] режим: {mode}")

    if mode == "ws":
        try:
            out, steps = run_ws(text, args.input, args.max_steps)
            print(f"[+] whitespace: шагов={steps}")
            print("  out:", repr(out[:500]))
            flags = common.find_flags(out.encode("utf-8", "replace"))
            for f in flags:
                print("  !!! ФЛАГ:", f)
            if auto and not flags:
                # это могли быть просто биты space/tab — покажем и их
                for name, data in decode_bits(text):
                    report(name, data)
        except Exception as e:
            print(f"[-] ws не выполнился: {e}; пробую bits")
            for name, data in decode_bits(text):
                report(name, data)
    elif mode == "bits":
        for name, data in decode_bits(text):
            report(name, data)
    elif mode == "zw":
        for name, data in decode_zero_width(text):
            report(name, data)
    elif mode == "vs":
        for name, data in decode_variation(text):
            report(name, data)
    elif mode == "tags":
        for name, data in decode_tags(text):
            report(name, data)
    elif mode == "braille":
        for name, data in decode_braille(text):
            report(name, data)
    elif mode == "trail":
        hit_flags = []
        for name, data in decode_trailing(text):
            hit_flags.extend(common.find_flags(data))
            report(name, data)
        if auto and not hit_flags:
            print("\n[i] в хвостах ничего осмысленного — перебираю схемы")
            run_brute(text)
    elif mode == "brute":
        run_brute(text)
    elif mode == "rtf":
        rtf_report(args.file, args.password)
    elif mode == "report":
        run_structure(text)
        run_brute(text)
    elif mode == "snow":
        run_snow(text, args.out, args.password)


if __name__ == "__main__":
    try:
        main()
    except (FileNotFoundError, IsADirectoryError, PermissionError) as e:
        print(f"[-] не могу открыть: {getattr(e, 'filename', None) or e}")
    except BrokenPipeError:
        pass
    except KeyboardInterrupt:
        print("\n[-] прервано")
