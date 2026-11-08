#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
alpha.py — значения канала как ASCII (классика: PNG RGBA, alpha != 255).

  python alpha.py pic.png
  python alpha.py pic.png --channel r --only-nonzero
  python alpha.py pic.png --channel a --raw
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

from PIL import Image


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("image")
    ap.add_argument("--channel", default="a", choices=["r", "g", "b", "a"])
    ap.add_argument("--only-nonzero", action="store_true", help="брать только значения != 0")
    ap.add_argument("--raw", action="store_true", help="печатать числа, а не символы")
    args = ap.parse_args()

    im = Image.open(args.image).convert("RGBA")
    px = im.load()
    idx = {"r": 0, "g": 1, "b": 2, "a": 3}[args.channel]

    vals = []
    for y in range(im.height):
        for x in range(im.width):
            v = px[x, y][idx]
            if args.only_nonzero and v == 0:
                continue
            vals.append(v)

    if args.raw:
        print(vals[:400])
        return

    # если альфа: интересуют значения, отличные от 255 (обычная непрозрачность)
    if args.channel == "a" and not args.only_nonzero:
        vals = [v for v in vals if v != 255]

    text = "".join(chr(v) if 32 <= v < 127 or v in (9, 10, 13) else "." for v in vals)
    print("[+] как текст:")
    print(text[:2000])
    cut = text.find("}")
    if cut != -1:
        print("\n[+] до '}':", text[:cut + 1])


if __name__ == "__main__":
    try:
        main()
    except (FileNotFoundError, IsADirectoryError, PermissionError) as e:
        print(f"[-] не могу открыть: {getattr(e, 'filename', None) or e}")
    except BrokenPipeError:
        pass
    except KeyboardInterrupt:
        print("\n[-] прервано")
