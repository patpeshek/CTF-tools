#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ocr.py — текст с картинки: капчи, скриншоты, кадры, «флаг на фото».

  python ocr.py image.png
  python ocr.py image.png --scale 2 --threshold
  python ocr.py image.png --invert

Tesseract ищется в PATH и в стандартной папке установки; если его нет —
скрипт честно говорит об этом, а не падает трейсбеком.
"""
from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import common  # noqa: E402

TESS_PATHS = [
    r"C:\Program Files\Tesseract-OCR\tesseract.exe",
    r"C:\Program Files (x86)\Tesseract-OCR\tesseract.exe",
]


def tesseract_cmd():
    import shutil
    exe = shutil.which("tesseract")
    if exe:
        return exe
    for p in TESS_PATHS:
        if os.path.isfile(p):
            return p
    return None


def ocr_image(path, scale=2, threshold=False, invert=False, psm=6):
    try:
        import pytesseract
        from PIL import Image, ImageOps
    except ImportError:
        return None, "нет pytesseract/Pillow"
    exe = tesseract_cmd()
    if not exe:
        return None, "tesseract не найден"
    pytesseract.pytesseract.tesseract_cmd = exe
    try:
        img = Image.open(path)
    except Exception as e:
        return None, f"не открыть картинку: {e}"
    img = img.convert("RGB")
    if scale and scale != 1:
        img = img.resize((img.width * scale, img.height * scale), Image.LANCZOS)
    img = img.convert("L")
    if invert:
        img = ImageOps.invert(img)
    if threshold:
        img = img.point(lambda x: 0 if x < 140 else 255)
    try:
        text = pytesseract.image_to_string(img, config=f"--psm {psm}")
    except Exception as e:
        return None, f"tesseract: {e}"
    return text, None


def variants(text):
    """Кандидаты-флаги из OCR: пробелы, лишние буквы, типичные ошибки OCR."""
    import itertools
    import re as _re

    out = []
    for m in _re.finditer(r"[A-Za-z][A-Za-z0-9_]{1,20}\{[ -~]{3,200}\}", text):
        raw = m.group()
        brace = raw.find("{")
        prefix, body = raw[:brace], raw[brace + 1:-1]
        pref_variants = {prefix, prefix.lower(), prefix.capitalize()}
        # лишняя буква перед настоящим префиксом: cCampi{ -> Campi{
        if len(prefix) > 4 and prefix[0].lower() == prefix[1].lower():
            pref_variants.add(prefix[1:])
        base = body.replace("\n", " ").strip()
        bodies = {base, base.replace(" ", "_"), base.replace(" ", "")}
        bodies |= {b.replace("__", "_") for b in list(bodies)}
        CONF = {"O": "0", "o": "0", "l": "1", "I": "1", "S": "5",
                "B": "8", "Z": "2", "G": "6", "T": "7"}
        for b in list(bodies):
            pos = [i for i, ch in enumerate(b) if ch in CONF]
            if 0 < len(pos) <= 6:
                for combo in itertools.product([0, 1], repeat=len(pos)):
                    chars = list(b)
                    for bit, i in zip(combo, pos):
                        if bit:
                            chars[i] = CONF[b[i]]
                    bodies.add("".join(chars))
        for p in pref_variants:
            for b in bodies:
                cand = f"{p}{{{b}}}"
                if cand not in out:
                    out.append(cand)
    return out[:300]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("file")
    ap.add_argument("--scale", type=int, default=2)
    ap.add_argument("--threshold", action="store_true")
    ap.add_argument("--invert", action="store_true")
    ap.add_argument("--psm", type=int, default=6)
    ap.add_argument("--variants", action="store_true",
                    help="показать кандидатов с исправлением ошибок OCR")
    common.add_flag_args(ap)
    args = ap.parse_args()
    common.apply_flag_args(args)

    if not os.path.isfile(args.file):
        print(f"[-] нет файла: {args.file}")
        return
    text, err = ocr_image(args.file, args.scale, args.threshold, args.invert, args.psm)
    if err:
        print(f"[-] {err}")
        return
    print(f"[i] распознано символов: {len(text or '')}")
    for line in (text or "").splitlines():
        if line.strip():
            print("   ", line.strip()[:200])
    flags = common.find_flags((text or "").encode("utf-8", "replace"))
    for f in flags:
        print(f"[!!!] ФЛАГ: {f}")
    if args.variants and text:
        cands = variants(text)
        if cands:
            print(f"[i] кандидаты с исправлением OCR ({len(cands)}):")
            for c in cands[:60]:
                print("    [?] " + c)


if __name__ == "__main__":
    main()
