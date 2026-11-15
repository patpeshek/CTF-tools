"""relabel.py — переразметить уже собранный npz без повторного обхода архива.

Признаки не меняются, меняются только метки: правка `rev_features.label_of`
или `pwn_features.label_of` не требует снова читать 23 тысячи файлов.

  python ml/relabel.py --data F:\\AIproject\\ml-runs\\rev_v1.npz
"""
from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import numpy as np

import pwn_features
import rev_features

MAX_BYTES = 16 * 1024 * 1024


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", required=True)
    args = ap.parse_args()

    d = np.load(args.data, allow_pickle=True)
    paths = [str(p) for p in d["path"]]
    fam, fam_pwn, keep, hand = [], [], [], []
    for i, p in enumerate(paths):
        try:
            with open(p, "rb") as fh:
                data = fh.read(MAX_BYTES)
        except OSError:
            continue
        lab = rev_features.label_of(data)
        if lab not in rev_features.LABELS:
            continue
        keep.append(i)
        hand.append(rev_features.hand_features(data))   # признаки могли измениться
        fam.append(lab)
        fam_pwn.append(pwn_features.label_of(data) or "")

    base = os.path.splitext(args.data)[0]
    out_rev = base + "_relabel.npz"
    np.savez(out_rev,
             x_hand=np.stack(hand).astype(np.float32), x_hist=d["x_hist"][keep],
             x_bytes=d["x_bytes"][keep],
             y=np.array([rev_features.LABELS.index(f) for f in fam],
                        dtype=np.int16),
             family=np.array(fam), split=np.array([str(x) for x in d["split"][keep]]),
             path=np.array([paths[i] for i in keep]))
    print(f"[+] rev: {len(fam)} → {out_rev}")

    pidx = [k for k, f in enumerate(fam_pwn) if f]
    out_pwn = os.path.join(os.path.dirname(os.path.abspath(args.data)),
                           "pwn_v1_relabel.npz")
    np.savez(out_pwn,
             x_hand=np.stack([hand[k] for k in pidx]).astype(np.float32),
             x_hist=d["x_hist"][[keep[k] for k in pidx]],
             x_bytes=d["x_bytes"][[keep[k] for k in pidx]],
             y=np.array([pwn_features.LABELS.index(fam_pwn[k]) for k in pidx],
                        dtype=np.int16),
             family=np.array([fam_pwn[k] for k in pidx]),
             split=np.array([str(x) for x in d["split"][[keep[k] for k in pidx]]]),
             path=np.array([paths[keep[k]] for k in pidx]))
    print(f"[+] pwn: {len(pidx)} → {out_pwn}")

    for title, labels in (("rev", fam), ("pwn", [fam_pwn[k] for k in pidx])):
        counts = {}
        for f in labels:
            counts[f] = counts.get(f, 0) + 1
        print(f"  {title}:")
        for name, cnt in sorted(counts.items(), key=lambda kv: -kv[1]):
            print(f"    {name:16s} {cnt}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
