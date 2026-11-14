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
    ap.add_argument("x", type=int, nargs="?")
    ap.add_argument("y", type=int, nargs="?")
    ap.add_argument("--channel", default="r", choices=["r", "g", "b", "a"])
    ap.add_argument("--palette", action="store_true",
                    help="выгрузить палитру и её XOR-варианты")
    ap.add_argument("--raw", action="store_true")
    args = ap.parse_args()

    img = Image.open(args.gif)
    if args.palette or args.x is None or args.y is None:
        pal = img.getpalette() or []
        print("[+] палитра:", len(pal) // 3, "цветов")
        data = bytes(pal)
        print("[+] hex:", data.hex()[:4000])
        best = None
        for k in (0x00, 0x80, 0xFF, 0x7F, 0xAA, 0x55):
            dec = bytes(c ^ k for c in data)
            try:
                txt = dec.decode("latin-1")
            except Exception:
                continue
            pr = sum(32 <= c < 127 for c in dec) / max(1, len(dec))
            if pr >= 0.8:
                print(f"[+] xor {k:#04x} printable={pr:.2f}: {txt}")
                if best is None:
                    best = k
        if best is None:
            print("[i] палитра как текст не читается — другие каналы/кадры")
        # канал с постоянным фоном: например все (g,b)=(0x11,0x22), а r — данные
        trip = [(pal[i], pal[i + 1], pal[i + 2])
                for i in range(0, len(pal) - 2, 3)]
        counts = {}
        for _, g, b in trip:
            counts[(g, b)] = counts.get((g, b), 0) + 1
        for (g, b), cnt in sorted(counts.items(), key=lambda kv: -kv[1])[:4]:
            if cnt < 8:
                continue
            seq = bytes(r for r, gg, bb in trip if (gg, bb) == (g, b))
            for k in (0x80, 0xFF, 0x7F, 0x00):
                dec = bytes(x ^ k for x in seq)
                pr = sum(32 <= x < 127 for x in dec) / max(1, len(dec))
                if pr >= 0.8:
                    print(f"[+] палитра: (g,b)=({g:#04x},{b:#04x}) n={cnt}, "
                          f"r xor {k:#04x}: {dec.decode('latin-1')}")
        info = {k: v for k, v in (img.info or {}).items()
                if isinstance(v, (str, int))}
        if info:
            print("[+] info:", info)
        return

    idx = {"r": 0, "g": 1, "b": 2, "a": 3}[args.channel]
    vals = []
    for frame in ImageSequence.Iterator(img):
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
