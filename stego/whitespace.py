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
                    choices=["auto", "ws", "bits", "zw", "vs", "tags", "braille", "trail"])
    ap.add_argument("--input", default="", help="вход для whitespace read")
    ap.add_argument("--max-steps", type=int, default=5_000_000)
    common.add_flag_args(ap)
    args = ap.parse_args()
    common.apply_flag_args(args)

    text = open(args.file, "r", encoding="utf-8", errors="replace").read()
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
        for name, data in decode_trailing(text):
            report(name, data)


if __name__ == "__main__":
    try:
        main()
    except (FileNotFoundError, IsADirectoryError, PermissionError) as e:
        print(f"[-] не могу открыть: {getattr(e, 'filename', None) or e}")
    except BrokenPipeError:
        pass
    except KeyboardInterrupt:
        print("\n[-] прервано")
