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

def tokenize(prog: str):
    code = [c for c in prog if c in (S, T, L)]
    i = 0
    out = []

    def rd():
        nonlocal i
        if i >= len(code):
            raise ValueError("EOF")
        c = code[i]
        i += 1
        return c

    def num():
        nonlocal i
        sign = 1
        c = rd()
        if c == T:
            sign = -1
        elif c != S:
            raise ValueError("bad number sign")
        val = 0
        while True:
            c = rd()
            if c == L:
                break
            val = val * 2 + (1 if c == T else 0)
        return sign * val

    while i < len(code):
        a = rd()
        if a == S:
            b = rd()
            if b == S:
                out.append(("push", num()))
            elif b == L:
                c = rd()
                if c == S:
                    out.append(("dup", None))
                elif c == T:
                    out.append(("discard", None))
                elif c == L:
                    out.append(("slide", num()))
                else:
                    raise ValueError("bad stack op")
            else:  # b == T
                c = rd()
                if c == S:
                    out.append(("swap", None))
                elif c == L:
                    out.append(("copy", num()))
                else:
                    raise ValueError("bad stack op")
        elif a == T:
            b = rd()
            if b == S:
                c = rd()
                if c == S:
                    d = rd()
                    op = {S: "add", T: "sub", L: "mul"}[d]
                    out.append((op, None))
                elif c == T:
                    d = rd()
                    op = {S: "div", T: "mod", L: "store"}[d]
                    out.append((op, None))
                else:
                    d = rd()
                    if d != S:
                        raise ValueError("bad heap op")
                    out.append(("retrieve", None))
            else:
                c = rd()
                if c == S:
                    d = rd()
                    op = {S: "outchar", T: "outnum", L: "readchar"}[d]
                    out.append((op, None))
                elif c == T:
                    d = rd()
                    if d != S:
                        raise ValueError("bad io op")
                    out.append(("readnum", None))
                else:
                    raise ValueError("bad io")
        else:  # L
            b = rd()
            if b == L:
                c = rd()
                if c != L:
                    raise ValueError("bad end")
                out.append(("end", None))
                break
            c = rd()
            if b == S:
                if c == S:
                    d = rd()
                    op = {S: "label", T: "call", L: "jump"}[d]
                    out.append((op, num()))
                else:
                    d = rd()
                    op = {S: "jz", T: "jn", L: "ret"}[d]
                    out.append((op, num() if op != "ret" else None))
            else:
                raise ValueError("bad flow")
    return out


def run_ws(prog: str, inp: str = "", max_steps: int = 5_000_000):
    ops = tokenize(prog)
    labels = {arg: idx for idx, (op, arg) in enumerate(ops) if op == "label"}
    stack, heap, calls = [], {}, []
    pc, out, steps = 0, [], 0
    inp_pos = 0
    while pc < len(ops) and steps < max_steps:
        steps += 1
        op, arg = ops[pc]
        pc += 1
        if op == "push":
            stack.append(arg)
        elif op == "dup":
            stack.append(stack[-1])
        elif op == "swap":
            stack[-1], stack[-2] = stack[-2], stack[-1]
        elif op == "discard":
            stack.pop()
        elif op == "copy":
            stack.append(stack[-arg])
        elif op == "slide":
            if arg:
                del stack[-arg:]
        elif op == "add":
            b, a = stack.pop(), stack.pop()
            stack.append(a + b)
        elif op == "sub":
            b, a = stack.pop(), stack.pop()
            stack.append(a - b)
        elif op == "mul":
            b, a = stack.pop(), stack.pop()
            stack.append(a * b)
        elif op == "div":
            b, a = stack.pop(), stack.pop()
            stack.append(int(a / b))
        elif op == "mod":
            b, a = stack.pop(), stack.pop()
            stack.append(a % b)
        elif op == "store":
            v, addr = stack.pop(), stack.pop()
            heap[addr] = v
        elif op == "retrieve":
            stack.append(heap.get(stack.pop(), 0))
        elif op == "outchar":
            out.append(chr(stack.pop() & 0xFF))
        elif op == "outnum":
            out.append(str(stack.pop()))
        elif op == "readchar":
            if inp_pos < len(inp):
                stack.append(ord(inp[inp_pos]))
                inp_pos += 1
            else:
                stack.append(0)
        elif op == "readnum":
            stack.append(0)
        elif op == "label":
            pass
        elif op == "call":
            calls.append(pc)
            pc = labels.get(arg, pc)
        elif op == "jump":
            pc = labels.get(arg, pc)
        elif op == "jz":
            if stack.pop() == 0:
                pc = labels.get(arg, pc)
        elif op == "jn":
            if stack.pop() < 0:
                pc = labels.get(arg, pc)
        elif op == "ret":
            pc = calls.pop() if calls else len(ops)
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
    if mode == "auto":
        if any(0xFE00 <= ord(c) <= 0xFE0F for c in text):
            mode = "vs"
        elif any(0xE0000 <= ord(c) <= 0xE007F for c in text):
            mode = "tags"
        elif any(c in ZW for c in text):
            mode = "zw"
        elif any(0x2800 <= ord(c) <= 0x28FF for c in text):
            mode = "braille"
        elif any(line != line.rstrip(" \t") for line in text.splitlines()):
            mode = "trail"
        elif all(c in (S, T, L, "\r") for c in text):
            mode = "ws"
        else:
            mode = "bits"
        print(f"[i] режим: {mode}")

    if mode == "ws":
        try:
            out, steps = run_ws(text, args.input, args.max_steps)
            print(f"[+] whitespace: шагов={steps}")
            print("  out:", repr(out[:500]))
            for f in common.find_flags(out.encode("utf-8", "replace")):
                print("  !!! ФЛАГ:", f)
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
