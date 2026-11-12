#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
lsb_brute.py — перебор LSB-раскладок (аналог zsteg -a) для любой картинки,
которую открывает Pillow: PNG/BMP/TIFF/WEBP/GIF/JPEG.

Перебирает: плоскость бит 1..8, порядок каналов (rgb, bgr, r, g, b, a, rgba,
abgr), обход пикселей (xy — по строкам, yx — по столбцам), порядок бит
(msb/lsb-first). Печатает лучшие раскладки, флаг — первым.

Примеры:
  python lsb_brute.py pic.png
  python lsb_brute.py pic.bmp --top 10
"""
from __future__ import annotations

# Windows: консоль/pipe не должны падать на Unicode.
try:
    import sys as _sys
    for _stream in (_sys.stdout, _sys.stderr):
        _stream.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

import argparse
import os
import sys

import numpy as np
from PIL import Image

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import common  # noqa: E402

CHANNEL_SETS = {
    "rgb": (0, 1, 2), "bgr": (2, 1, 0),
    "r": (0,), "g": (1,), "b": (2,), "a": (3,),
    "rgba": (0, 1, 2, 3), "abgr": (3, 2, 1, 0),
}
MAX_BYTES = 1 << 16          # сколько байт потока анализируем на раскладку
Image.MAX_IMAGE_PIXELS = None


def load_rgba(path):
    """Формато-независимая загрузка: любой формат Pillow -> HxWx4 uint8."""
    with Image.open(path) as im:
        im.load()
        return np.asarray(im.convert("RGBA"), dtype=np.uint8)


def stream(arr, chans, plane, traversal, msb_first):
    """Байтовый поток для одной раскладки (не больше MAX_BYTES)."""
    sub = arr[..., list(chans)]
    if traversal == "yx":
        sub = sub.transpose(1, 0, 2)
    need = MAX_BYTES * 8 // max(1, len(chans)) + 1     # пикселей достаточно
    flat = sub.reshape(-1, len(chans))[:need]
    bits = ((flat >> plane) & 1).astype(np.uint8).ravel()[:MAX_BYTES * 8]
    bits = bits[:len(bits) // 8 * 8]
    return np.packbits(bits, bitorder="big" if msb_first else "little").tobytes()


def score(data: bytes):
    """(балл, строки флагов). Флаг перевешивает всё."""
    if not data or not any(data[:256]):
        return 0.0, []
    flags = common.find_flags(data)
    head = data[:256]
    s = common.printable_ratio(head) * 100
    run = best = 0
    for c in head:
        run = run + 1 if 32 <= c < 127 else 0
        best = max(best, run)
    s += min(best, 60) / 2
    if flags:
        s += 1000
    return s, flags


def brute(arr):
    has_alpha = bool((arr[..., 3] != 255).any())
    res = []
    for cname, chans in CHANNEL_SETS.items():
        if 3 in chans and not has_alpha:
            continue
        for plane in range(8):
            for trav in ("xy", "yx"):
                for msb in (True, False):
                    data = stream(arr, chans, plane, trav, msb)
                    s, flags = score(data)
                    if s > 0:
                        res.append((s, flags, cname, plane + 1, trav,
                                    "msb" if msb else "lsb", data))
    res.sort(key=lambda r: -r[0])
    return res


def preview(data: bytes, n=100):
    return "".join(chr(c) if 32 <= c < 127 else "." for c in data[:n])


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("image")
    ap.add_argument("--top", type=int, default=5, help="сколько раскладок показать")
    args = ap.parse_args()

    try:
        arr = load_rgba(args.image)
    except (FileNotFoundError, IsADirectoryError, PermissionError) as e:
        print(f"[-] не могу открыть: {getattr(e, 'filename', None) or args.image}")
        return
    except Exception as e:
        print(f"[-] не картинка ({type(e).__name__}): {args.image}")
        return

    res = brute(arr)
    print(f"[i] {args.image}: {arr.shape[1]}x{arr.shape[0]}, "
          f"раскладок с данными: {len(res)}")
    shown = 0
    for s, flags, cname, plane, trav, bo, data in res[:max(1, args.top)]:
        tag = f"{cname} bit{plane} {trav} {bo}-first"
        if flags:
            print(f"[+] ФЛАГ ({tag}): {flags[0]}")
        else:
            print(f"[i] {tag}  score={s:.0f}: {preview(data)}")
        shown += 1
    if not shown:
        print("[-] читаемых раскладок нет")


if __name__ == "__main__":
    try:
        main()
    except BrokenPipeError:
        pass
    except KeyboardInterrupt:
        print("\n[-] прервано")
