#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
gif_frames.py — по одному пикселю с каждого кадра.

Координаты обычно лежат в имени файла, например 228x69.gif.

  python gif_frames.py ayanami.gif 228 69
  python gif_frames.py ayanami.gif 228 69 --channel r --raw
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

from PIL import Image, ImageSequence


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("gif")
    ap.add_argument("x", type=int)
    ap.add_argument("y", type=int)
    ap.add_argument("--channel", default="r", choices=["r", "g", "b", "a"])
    ap.add_argument("--raw", action="store_true")
    args = ap.parse_args()

    idx = {"r": 0, "g": 1, "b": 2, "a": 3}[args.channel]
    vals = []
    for frame in ImageSequence.Iterator(Image.open(args.gif)):
        rgb = frame.convert("RGBA")
        vals.append(rgb.getpixel((args.x, args.y))[idx])

    if args.raw:
        print(vals[:300])
        return
    text = "".join(chr(v) if 32 <= v < 127 else "." for v in vals)
    print("[+] кадров:", len(vals))
    print(text)
    cut = text.find("}")
    if cut != -1:
        print("\n[+] до '}':", text[:cut + 1])


if __name__ == "__main__":
    main()
