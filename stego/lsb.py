#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
lsb.py — LSB-стеганография: каналы R,G,B подряд, один канал, несколько бит,
разница двух картинок.

Примеры:
  python lsb.py pic.png                  # R,G,B,R,G,B… + RGBA/BGR/каналы по одному
  python lsb.py pic.png --channel rgba
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


# порядок каналов внутри пикселя (индексы в RGBA)
SEQS = {"rgb": (0, 1, 2), "rbg": (0, 2, 1), "grb": (1, 0, 2),
        "gbr": (1, 2, 0), "brg": (2, 0, 1), "bgr": (2, 1, 0),
        "rgba": (0, 1, 2, 3),
        "r": (0,), "g": (1,), "b": (2,), "a": (3,)}


def load_rgba(path) -> bytes:
    return Image.open(path).convert("RGBA").tobytes()


def bits_from_image(path, channel="all", nbits=1, order="lsb", offset=0):
    """Биты по пикселям (row-major), внутри пикселя — каналы в порядке SEQS.

    "all" = классика R,G,B,R,G,B… (альфа не подмешивается); RGBA, BGR и
    каналы по одному main() пробует отдельно. path — файл или RGBA-байты.
    Возвращает bytes из 0/1.
    """
    raw = path if isinstance(path, (bytes, bytearray)) else load_rgba(path)
    seq = SEQS["rgb" if channel == "all" else channel]
    raw = raw[max(0, offset) * 4:]
    k = len(seq)
    if k == 4:
        data = raw
    elif k == 1:
        data = raw[seq[0]::4]
    else:
        data = bytearray(len(raw) // 4 * k)
        for j, c in enumerate(seq):
            data[j::k] = raw[c::4]
    shifts = range(nbits) if order == "lsb" else range(nbits - 1, -1, -1)
    table = [bytes((v >> s) & 1 for s in shifts) for v in range(256)]
    return b"".join(map(table.__getitem__, data))


def bits_cycle(raw, order=(0, 1, 2), nbits=1, bit_order="lsb", offset=0):
    """Один бит на пиксель, каналы циклически: R,B,G,R,B,G…

    Так пишут, когда «по одному биту в пиксель», но канал меняют по кругу;
    это не то же самое, что каналы подряд (planes).
    """
    bits = []
    total = len(raw) // 4
    shifts = range(nbits) if bit_order == "lsb" else range(nbits - 1, -1, -1)
    for i in range(offset, total):
        c = order[(i - offset) % len(order)]
        v = raw[i * 4 + c]
        for s in shifts:
            bits.append((v >> s) & 1)
    return bytes(bits)


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


_TO_ASCII01 = bytes.maketrans(b"\x00\x01", b"01")


def bits_to_bytes(bits):
    n = len(bits) // 8 * 8
    if not n:
        return b""
    return int(bytes(bits[:n]).translate(_TO_ASCII01), 2).to_bytes(n // 8, "big")


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
    ap.add_argument("--channel", default="all",
                    choices=["all", "rgb", "rbg", "grb", "gbr", "brg", "bgr",
                             "rgba", "r", "g", "b", "a"],
                    help="all = R,G,B подряд + перебор каналов и порядков")
    ap.add_argument("--bits", type=int, default=1)
    ap.add_argument("--order", default="lsb", choices=["lsb", "msb"])
    ap.add_argument("--offset", type=int, default=0)
    args = ap.parse_args()

    raw = None
    if args.diff:
        bits = bits_diff(args.image, args.diff,
                         args.channel if args.channel in ("r", "g", "b", "a") else "r",
                         args.bits, args.order)
    else:
        raw = load_rgba(args.image)
        bits = bits_from_image(raw, args.channel, args.bits, args.order, args.offset)
        if args.channel == "all":
            print("[i] каналы: R,G,B подряд (rgb)")

    data = bits_to_bytes(bits)
    show(data)

    # rgb может не совпасть со способом записи (с альфой, BGR, один канал) —
    # пробуем остальные и показываем только то, что похоже на текст/флаг
    if args.channel == "all" and raw is not None:
        for ch in ("rgba", "rbg", "grb", "gbr", "brg", "bgr", "r", "g", "b", "a"):
            try:
                d = bits_to_bytes(bits_from_image(raw, ch, args.bits,
                                                  args.order, args.offset))
            except Exception:
                continue
            if not d or d == data:
                continue
            if common.find_flags(d) or common.printable_ratio(d) > 0.92:
                print(f"\n[+] каналы {ch} дают читаемый результат:")
                show(d)
        # цикл по каналам: один бит на пиксель, R,B,G,R,B,G…
        for order in ((0, 1, 2), (0, 2, 1), (1, 0, 2),
                      (1, 2, 0), (2, 0, 1), (2, 1, 0)):
            try:
                d = bits_to_bytes(bits_cycle(raw, order, args.bits,
                                             args.order, args.offset))
            except Exception:
                continue
            if not d or d == data:
                continue
            if common.find_flags(d) or common.printable_ratio(d) > 0.92:
                name = "".join("rgb"[c] for c in order)
                print(f"\n[+] цикл каналов {name} даёт читаемый результат:")
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
