#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
lsb.py — LSB-стеганография: один канал, несколько бит, разница двух картинок.

Примеры:
  python lsb.py pic.png
  python lsb.py pic.png --channel r --bits 2
  python lsb.py two.png --diff one.png --channel r
  python lsb.py pic.png --order msb --offset 100
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

from PIL import Image

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import common  # noqa: E402


def bits_from_image(path, channel="all", nbits=1, order="lsb", offset=0):
    im = Image.open(path).convert("RGBA")
    px = im.load()
    ch = {"r": 0, "g": 1, "b": 2, "a": 3}
    order_idx = [0, 1, 2, 3] if channel == "all" else [ch[channel]]
    bits = []
    for y in range(im.height):
        for x in range(im.width):
            if offset > 0:
                offset -= 1
                continue
            p = px[x, y]
            for i in order_idx:
                v = p[i]
                for b in range(nbits):
                    bits.append((v >> (b if order == "lsb" else nbits - 1 - b)) & 1)
    return bits


def bits_diff(img_a, img_b, channel="r", nbits=1, order="lsb"):
    a = Image.open(img_a).convert("RGBA")
    b = Image.open(img_b).convert("RGBA")
    if a.size != b.size:
        print(f"[!] размеры разные: {a.size} vs {b.size}", file=sys.stderr)
    w, h = min(a.width, b.width), min(a.height, b.height)
    pa, pb = a.load(), b.load()
    idx = {"r": 0, "g": 1, "b": 2, "a": 3}[channel]
    bits = []
    for y in range(h):
        for x in range(w):
            va, vb = pa[x, y][idx], pb[x, y][idx]
            if va != vb:
                for k in range(nbits):
                    bits.append((vb >> (k if order == "lsb" else nbits - 1 - k)) & 1)
    return bits


def bits_to_bytes(bits):
    out = bytearray()
    for i in range(0, len(bits) - 7, 8):
        val = 0
        for b in bits[i:i + 8]:
            val = (val << 1) | b
        out.append(val)
    return bytes(out)


def show(data: bytes):
    text = data.decode("utf-8", "replace")
    # до первого } — обычно там флаг
    cut = text.find("}")
    if cut != -1:
        print("\n[+] до '}':")
        print(text[:cut + 1])
    print("\n[+] как текст (первые 600 символов, непечатное = '.'):")
    print("".join(c if 32 <= ord(c) < 127 or c in "\n\r\t" else "." for c in text[:600]))
    print("\n[+] hex (первые 96 байт):")
    print(data[:96].hex())


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("image")
    ap.add_argument("--diff", help="вторая картинка: читать биты там, где канал отличается")
    ap.add_argument("--channel", default="all", choices=["r", "g", "b", "a", "all"])
    ap.add_argument("--bits", type=int, default=1)
    ap.add_argument("--order", default="lsb", choices=["lsb", "msb"])
    ap.add_argument("--offset", type=int, default=0)
    args = ap.parse_args()

    if args.diff:
        bits = bits_diff(args.image, args.diff, args.channel if args.channel != "all" else "r",
                         args.bits, args.order)
    else:
        bits = bits_from_image(args.image, args.channel, args.bits, args.order, args.offset)

    data = bits_to_bytes(bits)
    show(data)

    # «все каналы» может размазать данные, если писали в один канал —
    # пробуем каждый отдельно и показываем только то, что похоже на текст/флаг
    if args.channel == "all" and not args.diff:
        for ch in ("r", "g", "b", "a"):
            try:
                d = bits_to_bytes(bits_from_image(args.image, ch, args.bits,
                                                  args.order, args.offset))
            except Exception:
                continue
            if not d or d == data:
                continue
            if common.find_flags(d) or common.printable_ratio(d) > 0.92:
                print(f"\n[+] канал {ch} даёт читаемый результат:")
                show(d)


if __name__ == "__main__":
    try:
        main()
    except (FileNotFoundError, IsADirectoryError, PermissionError) as e:
        print(f"[-] не могу открыть: {getattr(e, 'filename', None) or e}")
    except BrokenPipeError:
        pass
    except KeyboardInterrupt:
        print("\n[-] прервано")
