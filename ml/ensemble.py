"""ensemble.py — усреднить вероятности нескольких моделей и замерить выигрыш.

MLP и char-transformer ошибаются по-разному: MLP опирается на признаки,
трансформер — на первые 256 байт. Усреднение softmax обычно даёт +2-4%
бесплатно, но только если это подтверждено замером, а не «так принято».

  python ml/ensemble.py --data ...\real_v2.npz ^
      --models ...\mlp_v12.pt ...\tf_v12.pt
  python ml/ensemble.py --data ...\data_v12_100k.npz --split test --models ...
"""
from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import numpy as np
import torch

from features import FEATURE_NAMES
from model import build


def load_model(path, device):
    ck = torch.load(path, map_location="cpu", weights_only=False)
    if len(ck["features"]) != len(FEATURE_NAMES):
        raise SystemExit(f"[-] {path}: {len(ck['features'])} признаков, "
                         f"а features.py даёт {len(FEATURE_NAMES)}")
    m = build(ck["arch"], len(ck["features"]), len(ck["families"]),
              **(ck.get("kw") or {}))
    m.load_state_dict(ck["model"])
    return m.to(device).eval(), ck["families"]


def probs_of(model, d, idx, device, batch=1024):
    out = []
    with torch.no_grad():
        for i in range(0, len(idx), batch):
            j = idx[i:i + batch]
            xb = torch.from_numpy(d["x_bytes"][j]).to(device)
            xh = torch.from_numpy(d["x_hand"][j]).to(device)
            xhist = torch.from_numpy(d["x_hist"][j]).to(device)
            out.append(torch.softmax(model(xb, xh, xhist).float(), dim=1).cpu().numpy())
    return np.concatenate(out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", required=True)
    ap.add_argument("--models", nargs="+", required=True)
    ap.add_argument("--split", default="", help="train/val/test/novel (пусто = все)")
    args = ap.parse_args()

    device = "cuda" if torch.cuda.is_available() else "cpu"
    d = np.load(args.data)
    n = len(d["family"])
    idx = np.arange(n)
    if args.split and "split" in d.files:
        idx = np.where(d["split"] == args.split)[0]
    fam = d["family"][idx]

    models = []
    families_ref = None
    for path in args.models:
        model, fams = load_model(path, device)
        if families_ref is None:
            families_ref = fams
        elif fams != families_ref:
            raise SystemExit(f"[-] {path}: другой набор классов")
        p = probs_of(model, d, idx, device)
        acc = float((np.array(fams)[p.argmax(1)] == fam).mean())
        print(f"    {os.path.basename(path):22s} acc={acc:.4f}")
        models.append(p)

    ens = np.mean(models, axis=0)
    acc = float((np.array(families_ref)[ens.argmax(1)] == fam).mean())
    print(f"[=] ансамбль ({len(models)} моделей): acc={acc:.4f} на {len(idx)} примерах")
    best_single = max(float((np.array(families_ref)[p.argmax(1)] == fam).mean())
                      for p in models)
    print(f"[=] выигрыш над лучшей одиночной: {acc - best_single:+.4f}")


if __name__ == "__main__":
    main()
