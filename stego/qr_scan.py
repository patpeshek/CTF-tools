#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
qr_scan.py — найти и прочитать QR на картинке (OpenCV, без pyzbar).

  python qr_scan.py pic.png
  python qr_scan.py pic.png --json

Пробует: оригинал, серый, увеличение, инверсию, OTSU-порог, квадранты.
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
import json
import os

import cv2
import numpy as np


def try_decode(img):
    det = cv2.QRCodeDetector()
    text, pts, _ = det.detectAndDecode(img)
    if text:
        return text
    return None


def candidates(img):
    yield "original", img
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY) if img.ndim == 3 else img
    yield "gray", gray
    for scale in (2.0, 3.0, 0.5):
        resized = cv2.resize(gray, None, fx=scale, fy=scale, interpolation=cv2.INTER_NEAREST)
        yield f"x{scale}", resized
    yield "invert", 255 - gray
    _, otsu = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
    yield "otsu", otsu
    yield "otsu_inv", 255 - otsu
    h, w = gray.shape[:2]
    for name, (y0, y1, x0, x1) in {
        "tl": (0, h // 2 + 20, 0, w // 2 + 20),
        "tr": (0, h // 2 + 20, w // 2 - 20, w),
        "bl": (h // 2 - 20, h, 0, w // 2 + 20),
        "br": (h // 2 - 20, h, w // 2 - 20, w),
    }.items():
        yield name, gray[y0:y1, x0:x1]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("image")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    img = cv2.imread(args.image, cv2.IMREAD_COLOR)
    if img is None:
        print("[-] не открылось:", args.image)
        return

    for name, cand in candidates(img):
        text = try_decode(cand)
        if text:
            if args.json:
                print(json.dumps({"file": args.image, "variant": name, "text": text},
                                 ensure_ascii=False))
            else:
                print(f"[+] QR найден ({name}): {text}")
            return

    if args.json:
        print(json.dumps({"file": args.image, "text": None}))
    else:
        print("[-] QR не найден. Попробуй обрезать/повернуть/увеличить картинку.")


if __name__ == "__main__":
    main()
