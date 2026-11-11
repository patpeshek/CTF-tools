#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
esolang.py — эзотерические языки, которые иногда попадаются в CTF.

  python esolang.py file
  python esolang.py file --lang bf --input "abc"
  python esolang.py --text "..."

Поддержано: Brainfuck, Ook!, Cow, Befunge-93, Deadfish, Whitespace.
Автодетект по алфавиту; если не уверен — печатает, что похоже.
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
import random
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import common      # noqa: E402
import whitespace  # noqa: E402


# ---------------- Brainfuck ----------------

def run_bf(code: str, inp: str = "", max_steps=5_000_000):
    code = "".join(c for c in code if c in "+-<>[].,")
    jump = {}
    st = []
    for i, c in enumerate(code):
        if c == "[":
            st.append(i)
        elif c == "]":
            if not st:
                raise ValueError("непарная ]")
            j = st.pop()
            jump[i], jump[j] = j, i
    tape = [0] * 30000
    ptr = pc = steps = ipos = 0
    out = []
    while pc < len(code) and steps < max_steps:
        steps += 1
        c = code[pc]
        if c == "+":
            tape[ptr] = (tape[ptr] + 1) & 0xFF
        elif c == "-":
            tape[ptr] = (tape[ptr] - 1) & 0xFF
        elif c == ">":
            ptr = (ptr + 1) % len(tape)
        elif c == "<":
            ptr = (ptr - 1) % len(tape)
        elif c == ".":
            out.append(chr(tape[ptr]))
        elif c == ",":
            tape[ptr] = ord(inp[ipos]) if ipos < len(inp) else 0
            ipos += 1
        elif c == "[":
            if tape[ptr] == 0:
                pc = jump[pc]
        elif c == "]":
            if tape[ptr] != 0:
                pc = jump[pc]
        pc += 1
    return "".join(out), steps


# ---------------- Ook! / Cow ----------------

OOK = {
    ("Ook.", "Ook?"): ">",
    ("Ook?", "Ook."): "<",
    ("Ook.", "Ook."): "+",
    ("Ook!", "Ook!"): "-",
    ("Ook!", "Ook."): ".",
    ("Ook.", "Ook!"): ",",
    ("Ook!", "Ook?"): "[",
    ("Ook?", "Ook!"): "]",
}

# COW: код инструкции = индекс в списке (спецификация языка)
COW_OPS = ["moo", "mOo", "moO", "mOO", "Moo", "MOo",
           "MoO", "MOO", "OOO", "MMM", "OOM", "oom"]
COW_RE = re.compile("|".join(COW_OPS))

# только то, что выражается в Brainfuck (для быстрых проверок вроде megaall);
# полноценное исполнение — run_cow()
COW = {
    "moO": ">", "mOo": "<", "MoO": "+", "MOo": "-",
    "Moo": ".", "MOO": "[", "moo": "]", "OOO": "[-]",
}


def ook_to_bf(text: str) -> str:
    toks = re.findall(r"Ook[.?!]", text)
    out = []
    for a, b in zip(toks[0::2], toks[1::2]):
        out.append(OOK.get((a, b), ""))
    return "".join(out)


def cow_to_bf(text: str) -> str:
    return "".join(COW.get(t, "") for t in COW_RE.findall(text))


def run_cow(code: str, inp: str = "", max_steps=5_000_000):
    """Интерпретатор COW по спецификации:
    0 moo  — конец цикла (назад к парному MOO)
    1 mOo  — ptr--          2 moO — ptr++
    3 mOO  — выполнить значение ячейки как инструкцию (3 = выход)
    4 Moo  — ячейка 0: прочитать символ, иначе напечатать символ
    5 MOo  — ячейка--       6 MoO — ячейка++
    7 MOO  — начало цикла: ячейка 0 → за парный moo
    8 OOO  — ячейка = 0     9 MMM — регистр: взять/положить
    10 OOM — напечатать число   11 oom — прочитать число
    """
    prog = [COW_OPS.index(t) for t in COW_RE.findall(code)]
    n = len(prog)
    jump = {}
    st = []
    for i, op in enumerate(prog):
        if op == 7:
            st.append(i)
        elif op == 0:
            if not st:
                raise ValueError("moo без парного MOO")
            j = st.pop()
            jump[i], jump[j] = j, i
    if st:
        raise ValueError("MOO без парного moo")

    def match(pc, op):
        # для MOO/moo, вызванных через mOO, — парная скобка ищется на месте
        if pc in jump and prog[pc] == op:
            return jump[pc]
        step, open_, close = (1, 7, 0) if op == 7 else (-1, 0, 7)
        depth, k = 0, pc + step
        while 0 <= k < n:
            if prog[k] == close:
                if depth == 0:
                    return k
                depth -= 1
            elif prog[k] == open_:
                depth += 1
            k += step
        return n if op == 7 else -1

    mem = [0]
    ptr = pc = steps = ipos = 0
    reg = None
    out = []
    while pc < n and steps < max_steps:
        steps += 1
        op = prog[pc]
        if op == 3:                      # mOO: выполнить ячейку как инструкцию
            op = mem[ptr]
            if op == 3 or not 0 <= op < len(COW_OPS):
                break
        if op == 0:                      # moo
            if mem[ptr] != 0:
                j = match(pc, 0)
                if j < 0:
                    break
                pc = j
        elif op == 1:
            if ptr == 0:
                break
            ptr -= 1
        elif op == 2:
            ptr += 1
            if ptr == len(mem):
                mem.append(0)
        elif op == 4:
            if mem[ptr] != 0:
                out.append(chr(mem[ptr] & 0xFF))
            else:
                mem[ptr] = ord(inp[ipos]) if ipos < len(inp) else 0
                ipos += 1
        elif op == 5:
            mem[ptr] -= 1
        elif op == 6:
            mem[ptr] += 1
        elif op == 7:                    # MOO
            if mem[ptr] == 0:
                pc = match(pc, 7)
        elif op == 8:
            mem[ptr] = 0
        elif op == 9:
            if reg is None:
                reg = mem[ptr]
            else:
                mem[ptr], reg = reg, None
        elif op == 10:
            out.append(f"{mem[ptr]}\n")
        elif op == 11:
            end = inp.find("\n", ipos)
            end = len(inp) if end == -1 else end
            m = re.match(r"\s*([+-]?\d+)", inp[ipos:end])
            mem[ptr] = int(m.group(1)) if m else 0
            ipos = end + 1
        pc += 1
    return "".join(out), steps


# ---------------- Befunge-93 ----------------

def run_befunge(code: str, inp: str = "", max_steps=2_000_000):
    lines = code.splitlines() or [""]
    w = max(len(l) for l in lines)
    grid = [list(l.ljust(w)) for l in lines]
    h = len(grid)
    x = y = 0
    dx, dy = 1, 0
    stack = []
    out = []
    string_mode = False
    steps = 0
    ipos = 0

    def pop():
        return stack.pop() if stack else 0

    while steps < max_steps:
        steps += 1
        if not (0 <= y < h and 0 <= x < w):
            break
        c = grid[y][x]
        if string_mode and c != '"':
            stack.append(ord(c))
        else:
            if c == '"':
                string_mode = not string_mode
            elif c.isdigit():
                stack.append(int(c))
            elif c == "+":
                stack.append(pop() + pop())
            elif c == "-":
                b, a = pop(), pop()
                stack.append(a - b)
            elif c == "*":
                stack.append(pop() * pop())
            elif c == "/":
                b, a = pop(), pop()
                stack.append(0 if b == 0 else a // b)
            elif c == "%":
                b, a = pop(), pop()
                stack.append(0 if b == 0 else a % b)
            elif c == "!":
                stack.append(0 if pop() else 1)
            elif c == "`":
                b, a = pop(), pop()
                stack.append(1 if a > b else 0)
            elif c == ">":
                dx, dy = 1, 0
            elif c == "<":
                dx, dy = -1, 0
            elif c == "^":
                dx, dy = 0, -1
            elif c == "v":
                dx, dy = 0, 1
            elif c == "?":
                dx, dy = random.choice([(1, 0), (-1, 0), (0, 1), (0, -1)])
            elif c == "_":
                dx, dy = ((1, 0) if pop() == 0 else (-1, 0))
            elif c == "|":
                dx, dy = ((0, 1) if pop() == 0 else (0, -1))
            elif c == '"':
                string_mode = True
            elif c == ":":
                v = pop() if not stack else stack[-1]
                stack.append(v)
            elif c == "\\":
                b, a = pop(), pop()
                stack += [b, a]
            elif c == "$":
                pop()
            elif c == ".":
                out.append(str(pop()))
            elif c == ",":
                out.append(chr(pop() & 0xFF))
            elif c == "#":
                x = (x + dx) % w
                y = (y + dy) % h
            elif c == "g":
                yy, xx = pop(), pop()
                stack.append(ord(grid[yy % h][xx % w]))
            elif c == "p":
                yy, xx, v = pop(), pop(), pop()
                grid[yy % h][xx % w] = chr(v & 0xFF)
            elif c == "&":
                stack.append(0)
            elif c == "~":
                c2 = inp[ipos] if ipos < len(inp) else "\x00"
                ipos += 1
                stack.append(ord(c2))
            elif c == "@":
                break
        x = (x + dx) % w
        y = (y + dy) % h
    return "".join(out), steps


# ---------------- Deadfish ----------------

def run_deadfish(code: str, max_steps=1_000_000):
    acc = 0
    out = []
    for c in code:
        if c == "i":
            acc += 1
        elif c == "d":
            acc -= 1
        elif c == "s":
            acc *= acc
        elif c == "o":
            out.append(str(acc))
        if acc == 256 or acc == -1:
            acc = 0
    return " ".join(out), len(code)


# ---------------- автодетект ----------------

def detect(text: str):
    body = "".join(c for c in text if not c.isspace())
    if not body:
        return "ws"
    if set(body) <= set("+-<>[].,"):
        return "bf"
    if "Ook" in text:
        return "ook"
    if any(k in text for k in ("MoO", "MOo", "moO", "mOo")):
        return "cow"
    if set(body) <= set("idso"):
        return "deadfish"
    if any(ch in text for ch in ("@", "v", "<", ">", "^", '"')) and "\n" in text:
        return "befunge"
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("file", nargs="?")
    ap.add_argument("--text")
    ap.add_argument("--lang", choices=["auto", "bf", "ook", "cow", "befunge", "deadfish", "ws"])
    ap.add_argument("--input", default="")
    ap.add_argument("--max-steps", type=int, default=5_000_000)
    common.add_flag_args(ap)
    args = ap.parse_args()
    common.apply_flag_args(args)

    if args.text is not None:
        text = args.text
    elif args.file:
        text = open(args.file, "r", encoding="utf-8", errors="replace").read()
    else:
        ap.error("нужен file или --text")

    lang = args.lang or "auto"
    if lang == "auto":
        lang = detect(text)
        print(f"[i] похоже на: {lang or 'неизвестно'}")
    if not lang:
        print("[-] не распознал. Попробуй --lang bf/ook/cow/befunge/deadfish/ws")
        return

    try:
        if lang == "bf":
            out, steps = run_bf(text, args.input, args.max_steps)
        elif lang == "ook":
            out, steps = run_bf(ook_to_bf(text), args.input, args.max_steps)
        elif lang == "cow":
            out, steps = run_cow(text, args.input, args.max_steps)
        elif lang == "befunge":
            out, steps = run_befunge(text, args.input, args.max_steps)
        elif lang == "deadfish":
            out, steps = run_deadfish(text, args.max_steps)
        else:
            out, steps = whitespace.run_ws(text, args.input, args.max_steps)
    except Exception as e:
        print(f"[-] ошибка выполнения: {e}")
        return

    print(f"[+] {lang}: шагов={steps}")
    print("  out:", repr(out[:1000]))
    for f in common.find_flags(out.encode("utf-8", "replace")):
        print("  !!! ФЛАГ:", f)


if __name__ == "__main__":
    try:
        main()
    except (FileNotFoundError, IsADirectoryError, PermissionError) as e:
        print(f"[-] не могу открыть: {getattr(e, 'filename', None) or e}")
    except BrokenPipeError:
        pass
    except KeyboardInterrupt:
        print("\n[-] прервано")
