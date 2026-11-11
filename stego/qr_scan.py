#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
qr_scan.py — найти и прочитать QR на картинке (OpenCV, без pyzbar).

  python qr_scan.py pic.png
  python qr_scan.py pic.png --json

Пробует: оригинал, серый, увеличение, инверсию, OTSU-порог, квадранты.
Прозрачный фон накладывается на белый; читает все QR на картинке.
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


def load_image(path):
    """(BGR uint8, альфа или None). Прозрачность — на белый фон: иначе
    прозрачные пиксели (обычно RGB=0) дают чёрный QR на чёрном."""
    try:
        from PIL import Image
        with Image.open(path) as im:
            im.load()
            alpha = None
            if im.mode in ("RGBA", "LA", "PA") or "transparency" in im.info:
                im = im.convert("RGBA")
                alpha = np.asarray(im)[:, :, 3].copy()
                bg = Image.new("RGBA", im.size, (255, 255, 255, 255))
                im = Image.alpha_composite(bg, im)
            rgb = np.asarray(im.convert("RGB"))
        return cv2.cvtColor(rgb, cv2.COLOR_RGB2BGR), alpha
    except Exception:
        pass
    # то, что PIL не открыл (np.fromfile — ещё и кириллица в пути)
    try:
        img = cv2.imdecode(np.fromfile(path, dtype=np.uint8), cv2.IMREAD_UNCHANGED)
    except (OSError, ValueError, cv2.error):
        return None, None
    if img is None:
        return None, None
    if img.dtype != np.uint8:
        img = (img.astype(np.float64) * 255 / max(1, img.max())).astype(np.uint8)
    if img.ndim == 2:
        return cv2.cvtColor(img, cv2.COLOR_GRAY2BGR), None
    if img.shape[2] == 4:
        a = img[:, :, 3:4].astype(np.float32) / 255
        rgb = img[:, :, :3].astype(np.float32) * a + 255 * (1 - a)
        return rgb.astype(np.uint8), img[:, :, 3].copy()
    return img[:, :, :3], None


def try_decode(img):
    """Все прочитанные тексты (несколько QR на одной картинке)."""
    det = cv2.QRCodeDetector()
    texts = []
    try:
        if hasattr(det, "detectAndDecodeMulti"):
            ok, decoded, _pts, _ = det.detectAndDecodeMulti(img)
            if ok:
                texts += [t for t in decoded if t]
        if not texts:
            text, _pts, _ = det.detectAndDecode(img)
            if text:
                texts.append(text)
    except cv2.error:
        pass
    return texts


def candidates(img, alpha=None):
    yield "original", img
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY) if img.ndim == 3 else img
    yield "gray", gray
    if alpha is not None and alpha.min() != alpha.max():
        # по одной альфе: непрозрачное — тёмные модули или светлые
        yield "alpha", 255 - alpha
        yield "alpha_inv", alpha
    h, w = gray.shape[:2]
    for scale in (2.0, 3.0, 0.5):
        if max(h, w) * scale > 4000 or min(h, w) * scale < 21:
            continue
        resized = cv2.resize(gray, None, fx=scale, fy=scale, interpolation=cv2.INTER_NEAREST)
        yield f"x{scale}", resized
    yield "invert", 255 - gray
    _, otsu = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
    yield "otsu", otsu
    yield "otsu_inv", 255 - otsu
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

    img, alpha = load_image(args.image)
    if img is None:
        print("[-] не открылось:", args.image)
        return

    # все варианты: на картинке может быть несколько QR, и разные варианты
    # читают разные коды
    found = {}
    for name, cand in candidates(img, alpha):
        for text in try_decode(cand):
            found.setdefault(text, name)

    if found:
        if args.json:
            codes = [{"variant": v, "text": t} for t, v in found.items()]
            print(json.dumps({"file": args.image, "variant": codes[0]["variant"],
                              "text": codes[0]["text"], "codes": codes},
                             ensure_ascii=False))
        else:
            for text, name in found.items():
                print(f"[+] QR найден ({name}): {text}")
        return

    if args.json:
        print(json.dumps({"file": args.image, "text": None}))
    else:
        print("[-] QR не найден. Попробуй обрезать/повернуть/увеличить картинку.")


if __name__ == "__main__":
    main()
