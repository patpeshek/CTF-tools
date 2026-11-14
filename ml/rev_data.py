"""rev_data.py — датасет бинарников для реверс-модели.

Берёт ELF/PE из архива (и из любых указанных папок), размечает их
детерминированно (`rev_features.label_of`) и сохраняет npz в той же форме,
что `gen_tasks.py`, чтобы обучение шло тем же `train.py`.

  python ml/rev_data.py --out F:\\AIproject\\ml-runs\\rev_v1.npz ^
      --roots F:\\AIproject\\ctf-files\\archive
"""
from __future__ import annotations

import argparse
import hashlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import numpy as np

from rev_features import (LABELS, byte_hist, byte_ids, hand_features,
                          label_of)

MAX_BYTES = 64 * 1024 * 1024
SKIP_DIRS = {".git", "__pycache__", "node_modules"}


def walk(roots):
    for root in roots:
        for dirpath, dirs, names in os.walk(root):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for n in sorted(names):
                p = os.path.join(dirpath, n)
                try:
                    if 0 < os.path.getsize(p) <= MAX_BYTES:
                        yield p
                except OSError:
                    continue


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--roots", nargs="+", required=True)
    args = ap.parse_args()

    hand, hist, ids, fam, paths = [], [], [], [], []
    seen = set()
    skipped = 0
    for p in walk(args.roots):
        try:
            with open(p, "rb") as fh:
                data = fh.read(MAX_BYTES)
        except OSError:
            skipped += 1
            continue
        if data[:4] != b"\x7fELF" and data[:2] != b"MZ":
            continue
        digest = hashlib.sha256(data).hexdigest()
        if digest in seen:          # один и тот же бинарник в разных папках
            skipped += 1
            continue
        seen.add(digest)
        label = label_of(data)
        if label not in LABELS:
            skipped += 1
            continue
        hand.append(hand_features(data))
        hist.append(byte_hist(data))
        ids.append(byte_ids(data))
        fam.append(label)
        paths.append(os.path.abspath(p))
        if len(fam) % 200 == 0:
            print(f"  {len(fam)} бинарников", flush=True)

    if not fam:
        print("[-] бинарников не нашлось")
        return 1

    rng = np.random.default_rng(1)
    n = len(fam)
    order = rng.permutation(n)
    split = np.array(["train"] * n, dtype=object)
    split[order[int(n * 0.70):int(n * 0.85)]] = "val"
    split[order[int(n * 0.85):]] = "test"

    np.savez(args.out,
             x_hand=np.stack(hand).astype(np.float32),
             x_hist=np.stack(hist).astype(np.float32),
             x_bytes=np.stack(ids).astype(np.int16),
             y=np.array([LABELS.index(f) for f in fam], dtype=np.int16),
             family=np.array(fam),
             split=split,
             path=np.array(paths))

    counts = {}
    for f in fam:
        counts[f] = counts.get(f, 0) + 1
    print(f"[+] бинарников: {n} (пропущено {skipped}) → {args.out}")
    for name, cnt in sorted(counts.items(), key=lambda kv: -kv[1]):
        print(f"    {name:14s} {cnt}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
