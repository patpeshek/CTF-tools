#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
obscure.py — редкие кодировки и шифры, которые бывают в CTF.

  python obscure.py auto --text "..."
  python obscure.py base58 --text "..."
  python obscure.py adfgx --text "..." --key "SECRET"
  python obscure.py adfgvx --text "..." --key "SECRET"
  python obscure.py bifid --text "..." --key "SECRET" --period 5
  python obscure.py porta --text "..." --key "SECRET"
  python obscure.py beaufort --text "..." --key "SECRET"
  python obscure.py gronsfeld --text "..." --key "31415"
  python obscure.py autokey --text "..." --key "SECRET"
  python obscure.py hill --text "..." --matrix "3,3,2,5"

auto: base58/62/91/85, base32hex, uuencode, quoted-printable, punycode,
Unicode escapes, HTML entities, A1Z26, Bacon, tap code, Polybius, keyboard shift.
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
import binascii
import codecs
import html
import quopri
import re
import string
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import autocrack as ac  # noqa: E402
import common           # noqa: E402

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
B62 = string.digits + string.ascii_uppercase + string.ascii_lowercase
A5 = "ABCDEFGHIKLMNOPQRSTUVWXYZ"  # без J
A6 = string.ascii_uppercase + string.digits


def b58decode(s: str) -> bytes:
    n = 0
    for c in s:
        n = n * 58 + B58.index(c)
    body = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    pad = len(s) - len(s.lstrip("1"))
    return b"\x00" * pad + body


def b62decode(s: str) -> bytes:
    n = 0
    for c in s:
        n = n * 62 + B62.index(c)
    return n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""


def b91decode(s: str) -> bytes:
    table = {c: i for i, c in enumerate(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
        "!#$%&()*+,./:;<=>?@[]^_`{|}~\"")}
    v = -1
    b = n = 0
    out = bytearray()
    for c in s:
        if c not in table:
            continue
        d = table[c]
        if v < 0:
            v = d
        else:
            v += d * 91
            b |= v << n
            n += 13 if (v & 8191) > 88 else 14
            while n > 7:
                out.append(b & 255)
                b >>= 8
                n -= 8
            v = -1
    if v + 1:
        out.append((b | v << n) & 255)
    return bytes(out)


def uudecode(text: str):
    out = bytearray()
    for line in text.splitlines():
        if not line or line.startswith(("begin", "end")):
            continue
        try:
            out += binascii.a2b_uu(line)
        except binascii.Error:
            continue
    return bytes(out)


def bacon(text: str):
    bits = "".join("1" if c.lower() == "b" else "0" if c.lower() == "a" else ""
                   for c in text)
    out = []
    for i in range(0, len(bits) - 4, 5):
        out.append(chr(65 + int(bits[i:i + 5], 2)))
    return "".join(out)


def a1z26(text: str):
    nums = [int(x) for x in re.findall(r"\d+", text)]
    if nums and all(1 <= n <= 26 for n in nums):
        return "".join(chr(64 + n) for n in nums)
    return None


def tap_code(text: str):
    digits = re.findall(r"[1-5]", text)
    out = []
    for i in range(0, len(digits) - 1, 2):
        r, c = int(digits[i]) - 1, int(digits[i + 1]) - 1
        out.append(A5[r * 5 + c])
    return "".join(out)


def polybius(text: str, alphabet=A5):
    digits = re.findall(r"[1-5]", text)
    out = []
    for i in range(0, len(digits) - 1, 2):
        idx = (int(digits[i]) - 1) * 5 + int(digits[i + 1]) - 1
        if 0 <= idx < len(alphabet):
            out.append(alphabet[idx])
    return "".join(out)


def keyboard_shift(text: str):
    rows = ["qwertyuiop", "asdfghjkl", "zxcvbnm"]
    out = []
    for direction in (-1, 1):
        res = []
        for c in text:
            low = c.lower()
            found = False
            for row in rows:
                if low in row:
                    idx = row.index(low) + direction
                    if 0 <= idx < len(row):
                        nc = row[idx]
                        res.append(nc.upper() if c.isupper() else nc)
                    else:
                        res.append(c)
                    found = True
                    break
            if not found:
                res.append(c)
        out.append("".join(res))
    return out


def try_decoders(text: str):
    cands = []

    def add(name, val):
        if isinstance(val, bytes):
            val = val.decode("utf-8", "replace")
        if val and isinstance(val, str):
            cands.append((name, val))

    t = text.strip()
    if re.fullmatch(r"[1-9A-HJ-NP-Za-km-z]{6,}", t):
        try:
            add("base58", b58decode(t))
        except Exception:
            pass
    if re.fullmatch(r"[0-9A-Za-z]{8,}", t):
        try:
            add("base62", b62decode(t))
        except Exception:
            pass
    if re.fullmatch(r"[A-Za-z0-9!#$%&()*+,./:;<=>?@\[\]^_`{|}~\"-]{6,}", t):
        try:
            add("base91", b91decode(t))
        except Exception:
            pass
    for name, fn in (("base85", base64.b85decode), ("ascii85", base64.a85decode)):
        try:
            add(name, fn(t))
        except Exception:
            pass
    if re.fullmatch(r"[0-9A-V]+=*", t) and len(t) >= 6:
        try:
            add("base32hex", base64.b32hexdecode(t + "=" * (-len(t) % 8)))
        except Exception:
            pass
    if re.search(r"=\r?\n", text) or text.startswith("begin "):
        try:
            add("uuencode", uudecode(text))
        except Exception:
            pass
    if re.search(r"=[0-9A-Fa-f]{2}", text):
        try:
            add("quoted-printable", quopri.decodestring(text.encode()).decode("utf-8", "replace"))
        except Exception:
            pass
    if "xn--" in text:
        try:
            parts = []
            for part in text.split("."):
                parts.append(codecs.decode(part[4:], "punycode") if part.startswith("xn--") else part)
            add("punycode", ".".join(parts))
        except Exception:
            pass
    if re.search(r"\\u[0-9a-fA-F]{4}", text):
        try:
            add("unicode-escape", text.encode().decode("unicode_escape"))
        except Exception:
            pass
    if re.search(r"&#?\w+;", text):
        add("html-entities", html.unescape(text))
    if re.fullmatch(r"[\d\s,.;:-]+", text):
        a = a1z26(text)
        if a:
            add("a1z26", a)
    if re.fullmatch(r"[ABab\s]+", text) and len(re.sub(r"\s", "", text)) % 5 == 0:
        add("bacon", bacon(text))
    if re.fullmatch(r"[1-5\s,.;:-]+", text):
        add("tap-code", tap_code(text))
        add("polybius", polybius(text))
    if any(c.isalpha() for c in text):
        for i, s in enumerate(keyboard_shift(text)):
            add(f"keyboard-{'left' if i == 0 else 'right'}", s)
    return cands


def columnar_decrypt(text: str, key: str) -> str:
    n = len(text)
    cols = len(key)
    rows = (n + cols - 1) // cols
    order = sorted(range(cols), key=lambda i: key[i])
    lengths = [n // cols + (1 if i < n % cols else 0) for i in range(cols)]
    grid = [[""] * cols for _ in range(rows)]
    idx = 0
    for c in order:
        for r in range(lengths[c]):
            grid[r][c] = text[idx]
            idx += 1
    return "".join("".join(row) for row in grid)


def square(key: str, alphabet: str):
    seen = []
    for c in key.upper() + alphabet:
        if c in alphabet and c not in seen:
            seen.append(c)
    return [seen[i * 5:(i + 1) * 5] for i in range(5)]


def square6(key: str):
    seen = []
    for c in (key.upper() + A6):
        if c in A6 and c not in seen:
            seen.append(c)
    return [seen[i * 6:(i + 1) * 6] for i in range(6)]


def adfgx_decrypt(text: str, key: str, alphabet6=False):
    alpha = A6 if alphabet6 else A5
    labels = "ADFGVX" if alphabet6 else "ADFGX"
    n = 6 if alphabet6 else 5
    text = re.sub(r"\s", "", text.upper())
    text = columnar_decrypt(text, key)
    sq = square6(key) if alphabet6 else square(key, A5)
    out = []
    for i in range(0, len(text) - 1, 2):
        a = labels.index(text[i]) if text[i] in labels else -1
        b = labels.index(text[i + 1]) if text[i + 1] in labels else -1
        if 0 <= a < n and 0 <= b < n:
            out.append(sq[a][b])
    return "".join(out)


def bifid_decrypt(text: str, key: str, period=5):
    sq = square(key, A5)
    pos = {sq[r][c]: (r, c) for r in range(5) for c in range(5)}
    out = []
    clean = re.sub(r"[^A-Z]", "", text.upper()).replace("J", "I")
    for start in range(0, len(clean), period):
        chunk = clean[start:start + period]
        coords = [pos[c] for c in chunk if c in pos]
        flat = [v for pair in coords for v in pair]
        half = len(coords)
        rows, cols = flat[:half], flat[half:half * 2]
        for r, c in zip(rows, cols):
            out.append(sq[r][c])
    return "".join(out)


def porta_decrypt(text: str, key: str):
    key = re.sub(r"[^A-Z]", "", key.upper())
    out = []
    ki = 0
    for c in text.upper():
        if not c.isalpha():
            out.append(c)
            continue
        i = (ord(key[ki % len(key)]) - 65) // 2
        first = string.ascii_uppercase[13 + i:] + string.ascii_uppercase[13:13 + i]
        row = first + "".join(chr((ord(x) - 65 - 13) % 26 + 65) for x in first)
        p = row.index(c)
        out.append(string.ascii_uppercase[p])
        ki += 1
    return "".join(out)


def beaufort(text: str, key: str):
    key = re.sub(r"[^A-Z]", "", key.upper())
    out = []
    ki = 0
    for c in text.upper():
        if not c.isalpha():
            out.append(c)
            continue
        k = ord(key[ki % len(key)]) - 65
        out.append(chr((k - (ord(c) - 65)) % 26 + 65))
        ki += 1
    return "".join(out)


def gronsfeld(text: str, key: str):
    digits = [int(x) for x in re.findall(r"\d", key)]
    out = []
    ki = 0
    for c in text.upper():
        if not c.isalpha():
            out.append(c)
            continue
        out.append(chr((ord(c) - 65 - digits[ki % len(digits)]) % 26 + 65))
        ki += 1
    return "".join(out)


def autokey(text: str, key: str):
    key = re.sub(r"[^A-Z]", "", key.upper())
    out = []
    out_letters = []
    ki = 0
    for c in text.upper():
        if not c.isalpha():
            out.append(c)
            continue
        k = ord(key[ki]) - 65 if ki < len(key) else ord(out_letters[-1]) - 65
        p = chr((ord(c) - 65 - k) % 26 + 65)
        out.append(p)
        out_letters.append(p)
        ki += 1
    return "".join(out)


def hill_decrypt(text: str, matrix):
    size = int(round(len(matrix) ** 0.5))
    # определитель и обратная матрица mod 26
    def det(m):
        if len(m) == 4:
            return (m[0] * m[3] - m[1] * m[2]) % 26
        if len(m) == 9:
            return (m[0] * (m[4] * m[8] - m[5] * m[7])
                    - m[1] * (m[3] * m[8] - m[5] * m[6])
                    + m[2] * (m[3] * m[7] - m[4] * m[6])) % 26
        return 0

    d = det(matrix)
    try:
        inv = pow(int(d), -1, 26)
    except ValueError:
        raise ValueError("детерминант не обратим mod 26")
    if size == 2:
        adj = [matrix[3], -matrix[1], -matrix[2], matrix[0]]
    else:
        adj = [
            matrix[4] * matrix[8] - matrix[5] * matrix[7],
            -(matrix[1] * matrix[8] - matrix[2] * matrix[7]),
            matrix[1] * matrix[5] - matrix[2] * matrix[4],
            -(matrix[3] * matrix[8] - matrix[5] * matrix[6]),
            matrix[0] * matrix[8] - matrix[2] * matrix[6],
            -(matrix[0] * matrix[5] - matrix[2] * matrix[3]),
            matrix[3] * matrix[7] - matrix[4] * matrix[6],
            -(matrix[0] * matrix[7] - matrix[1] * matrix[6]),
            matrix[0] * matrix[4] - matrix[1] * matrix[3],
        ]
    invmat = [(x * inv) % 26 for x in adj]
    clean = [ord(c) - 65 for c in re.sub(r"[^A-Z]", "", text.upper())]
    out = []
    for i in range(0, len(clean) - size + 1, size):
        block = clean[i:i + size]
        for r in range(size):
            out.append(chr(sum(invmat[r * size + c] * block[c] for c in range(size)) % 26 + 65))
    return "".join(out)


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("auto")
    a.add_argument("--text", required=True)
    a.add_argument("--min-score", type=float, default=1.0)
    a.add_argument("--show-noise", action="store_true")

    for name in ("base58", "base62", "base91", "bacon", "a1z26", "tap", "polybius"):
        p = sub.add_parser(name)
        p.add_argument("--text", required=True)
        if name in ("tap", "polybius"):
            p.add_argument("--alphabet", default=A5)

    for name in ("adfgx", "adfgvx", "bifid", "porta", "beaufort", "gronsfeld", "autokey"):
        p = sub.add_parser(name)
        p.add_argument("--text", required=True)
        p.add_argument("--key", required=True)
        if name == "bifid":
            p.add_argument("--period", type=int, default=5)

    h = sub.add_parser("hill")
    h.add_argument("--text", required=True)
    h.add_argument("--matrix", required=True, help="например 3,3,2,5 или 9 чисел")

    common.add_flag_args(ap)
    args = ap.parse_args()
    common.apply_flag_args(args)

    try:
        if args.cmd == "auto":
            cands = try_decoders(args.text)
            ranked = []
            for name, val in cands:
                ranked.append((ac.score_text(val), name, val))
            ranked.sort(key=lambda x: -x[0])
            for sc, name, val in ranked[:12]:
                flag = ac.find_flag(val)
                if flag is None and sc < getattr(args, "min_score", 1.0):
                    continue
                if flag is None and not getattr(args, "show_noise", False) and \
                        common.printable_ratio(val.encode("utf-8", "replace")) < 0.65:
                    continue
                print(f"\n[{'!!!' if flag else '   '}] score={sc:7.1f}  {name}")
                print("   ", val[:300])
                if flag:
                    print("    FLAG:", flag)
            if not ranked:
                print("[-] ничего не распознал")
            return
        if args.cmd == "base58":
            out = b58decode(args.text)
        elif args.cmd == "base62":
            out = b62decode(args.text)
        elif args.cmd == "base91":
            out = b91decode(args.text)
        elif args.cmd == "bacon":
            out = bacon(args.text).encode()
        elif args.cmd == "a1z26":
            out = (a1z26(args.text) or "").encode()
        elif args.cmd == "tap":
            out = tap_code(args.text).encode()
        elif args.cmd == "polybius":
            out = polybius(args.text, args.alphabet).encode()
        elif args.cmd in ("adfgx", "adfgvx"):
            out = adfgx_decrypt(args.text, args.key, args.cmd == "adfgvx").encode()
        elif args.cmd == "bifid":
            out = bifid_decrypt(args.text, args.key, args.period).encode()
        elif args.cmd == "porta":
            out = porta_decrypt(args.text, args.key).encode()
        elif args.cmd == "beaufort":
            out = beaufort(args.text, args.key).encode()
        elif args.cmd == "gronsfeld":
            out = gronsfeld(args.text, args.key).encode()
        elif args.cmd == "autokey":
            out = autokey(args.text, args.key).encode()
        elif args.cmd == "hill":
            matrix = [int(x) for x in re.findall(r"-?\d+", args.matrix)]
            out = hill_decrypt(args.text, matrix).encode()
        else:
            return
    except Exception as e:
        print("[-] ошибка:", e)
        return

    print("out:", out.decode("utf-8", "replace")[:500])
    for f in common.find_flags(out):
        print("!!! ФЛАГ:", f)


if __name__ == "__main__":
    main()
