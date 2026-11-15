"""rev_data.py — датасет бинарников для реверс-модели.

Берёт ELF/PE из архива (и из любых указанных папок), размечает их
детерминированно (`rev_features.label_of`) и сохраняет npz в той же форме,
что `gen_tasks.py`, чтобы обучение шло тем же `train.py`.

  python ml/rev_data.py --out F:\\AIproject\\ml-runs\\rev_v1.npz ^
      --roots F:\\AIproject\\ctf-files\\archive

Читаем не больше первых 4 МБ: признаки смотрят в первые 64 КБ, метка — в
первые 300 КБ, дальше всё равно мусор. На HDD это разница в разы.
"""
from __future__ import annotations

import argparse
import hashlib
import os
import sys
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import numpy as np

from rev_features import (LABELS, byte_hist, byte_ids, hand_features,
                          label_of)

MAX_BYTES = 4 * 1024 * 1024
SKIP_DIRS = {".git", "__pycache__", "node_modules"}


def walk(roots):
    for root in roots:
        for dirpath, dirs, names in os.walk(root):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for n in sorted(names):
                p = os.path.join(dirpath, n)
                try:
                    if 0 < os.path.getsize(p):
                        yield p
                except OSError:
                    continue


def one(p: str):
    """(метка rev, метка pwn, хэш, признаки) для файла; None — если не ELF/PE."""
    try:
        with open(p, "rb") as fh:
            data = fh.read(MAX_BYTES)
    except OSError:
        return None
    if data[:4] != b"\x7fELF" and data[:2] != b"MZ":
        return None
    label = label_of(data)
    if label not in LABELS:
        return None
    pwn = ""
    try:
        import pwn_features
        pwn = pwn_features.label_of(data)
    except Exception:
        pass
    return (label, pwn, hashlib.sha256(data).hexdigest(),
            hand_features(data), byte_hist(data), byte_ids(data), os.path.abspath(p))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--roots", nargs="+", required=True)
    ap.add_argument("--workers", type=int, default=8)
    args = ap.parse_args()

    files = list(walk(args.roots))
    print(f"[i] файлов в обходе: {len(files)}", flush=True)

    try:
        import pwn_features
    except Exception:               # pwn-метки необязательны
        pwn_features = None

    hand, hist, ids, fam, paths = [], [], [], [], []
    fam_pwn = []
    seen = set()
    skipped = 0
    done = 0
    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        for res in ex.map(one, files, chunksize=16):
            done += 1
            if done % 2000 == 0:
                print(f"  просмотрено {done}/{len(files)}, бинарников {len(fam)}",
                      flush=True)
            if res is None:
                continue
            label, pwn_label, digest, h, hh, ii, path = res
            if digest in seen:      # один и тот же бинарник в разных папках
                skipped += 1
                continue
            seen.add(digest)
            hand.append(h)
            hist.append(hh)
            ids.append(ii)
            fam.append(label)
            paths.append(path)
            fam_pwn.append(pwn_label)

    if not fam:
        print("[-] бинарников не нашлось")
        return 1

    rng = np.random.default_rng(1)
    n = len(fam)
    order = rng.permutation(n)
    split = np.array(["train"] * n)          # строки: train.py грузит без pickle
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

    # тот же набор файлов, но метки pwn-профиля — второй датасет бесплатно
    if pwn_features is not None:
        plabels = [f for f in fam_pwn if f]
        pidx = [i for i, f in enumerate(fam_pwn) if f]
        if plabels:
            pout = os.path.join(os.path.dirname(os.path.abspath(args.out)),
                                "pwn_v1.npz")
            np.savez(pout,
                     x_hand=np.stack([hand[i] for i in pidx]).astype(np.float32),
                     x_hist=np.stack([hist[i] for i in pidx]).astype(np.float32),
                     x_bytes=np.stack([ids[i] for i in pidx]).astype(np.int16),
                     y=np.array([pwn_features.LABELS.index(f) for f in plabels],
                                dtype=np.int16),
                     family=np.array(plabels),
                     split=split[pidx],
                     path=np.array([paths[i] for i in pidx]))
            pc = {}
            for f in plabels:
                pc[f] = pc.get(f, 0) + 1
            print(f"[+] pwn-датасет: {len(plabels)} → {pout}")
            for name, cnt in sorted(pc.items(), key=lambda kv: -kv[1]):
                print(f"    {name:16s} {cnt}")

    counts = {}
    for f in fam:
        counts[f] = counts.get(f, 0) + 1
    print(f"[+] бинарников: {n} (пропущено {skipped}) → {args.out}")
    for name, cnt in sorted(counts.items(), key=lambda kv: -kv[1]):
        print(f"    {name:14s} {cnt}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
