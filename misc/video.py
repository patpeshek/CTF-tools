#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""video.py — кадры из видео/GIF: текст, флаги, отличия между кадрами.

  python video.py clip.mp4
  python video.py clip.gif --every 5 --max 200
  python video.py clip.mp4 --no-ocr --diff

Кадры читаются через OpenCV (он уже стоит), текст — Tesseract, если есть.
Печатает то, что реально нашлось; ничего не выдумывает.
"""
from __future__ import annotations

import argparse
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import common  # noqa: E402


def frames(path, every=1, limit=300):
    try:
        import cv2
    except ImportError:
        print("[-] нет opencv-python")
        return []
    cap = cv2.VideoCapture(path)
    if not cap.isOpened():
        print("[-] не открыть видео")
        return []
    out = []
    idx = 0
    saved = 0
    base = os.path.join(tempfile.gettempdir(), "solve_video",
                        os.path.basename(path).replace(".", "_"))
    os.makedirs(base, exist_ok=True)
    while saved < limit:
        ok, frame = cap.read()
        if not ok:
            break
        if idx % max(1, every) == 0:
            p = os.path.join(base, f"frame_{idx:06d}.png")
            try:
                cv2.imwrite(p, frame)
                out.append((idx, p))
            except Exception:
                pass
            saved += 1
        idx += 1
    cap.release()
    print(f"[i] кадров прочитано: {idx}, сохранено: {len(out)}")
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("file")
    ap.add_argument("--every", type=int, default=3)
    ap.add_argument("--max", type=int, default=200)
    ap.add_argument("--no-ocr", action="store_true")
    ap.add_argument("--diff", action="store_true", help="кадры, отличающиеся от соседних")
    common.add_flag_args(ap)
    args = ap.parse_args()
    common.apply_flag_args(args)

    if not os.path.isfile(args.file):
        print(f"[-] нет файла: {args.file}")
        return
    fr = frames(args.file, args.every, args.max)
    if not fr:
        return

    if args.diff:
        try:
            import numpy as np
            from PIL import Image
            prev = None
            changed = []
            for idx, p in fr:
                im = np.asarray(Image.open(p).convert("L").resize((160, 90)))
                if prev is not None:
                    score = float(np.abs(im.astype(int) - prev.astype(int)).mean())
                    if score > 4:
                        changed.append((idx, p, score))
                prev = im
            print(f"[i] заметно отличающихся кадров: {len(changed)}")
            for idx, p, score in changed[:40]:
                print(f"    кадр {idx}: {p} (diff={score:.1f})")
            fr = [(i, p) for i, p, _ in changed] or fr
        except Exception as e:
            print(f"[!] diff не сработал: {e}")

    if args.no_ocr:
        for idx, p in fr[:40]:
            print(f"    кадр {idx}: {p}")
        return

    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import ocr as ocr_mod

    hits = 0
    for idx, p in fr:
        text, err = ocr_mod.ocr_image(p, scale=2, threshold=True, psm=6)
        if err or not text:
            continue
        clean = " ".join(text.split())
        if not clean:
            continue
        letters = sum(ch.isalnum() for ch in clean)
        wordy = letters >= 6 and letters / max(1, len(clean)) > 0.55
        flags = common.find_flags(clean.encode("utf-8", "replace"))
        if flags or wordy:
            print(f"[кадр {idx}] {clean[:180]}")
        for f in flags:
            print(f"[!!!] ФЛАГ: {f}")
            hits += 1
        if flags:
            break
    if not hits:
        print("[i] точного флага в кадрах нет; текст выше — глазами, "
              "или попробуй --every 1 --max 200")


if __name__ == "__main__":
    main()
