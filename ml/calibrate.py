"""calibrate.py — temperature scaling: научить модель честно говорить «не знаю».

Проблема: на невиданных семействах softmax уверен (0.6+), хотя ошибается.
Классическая калибровка (минимум NLL на val) здесь идёт **не туда**: val —
синтетика с label smoothing, модель там недоуверена, и подбор даёт T < 1,
то есть ещё больше уверенности. Поэтому печатаем таблицу по T и выбираем
температуру по правилу «на OOD в среднем не больше 0.5, синтетику не портим».

  python ml/calibrate.py --model ...\\mlp_v12.pt --data ...\\data_v12_100k.npz
"""
from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import numpy as np
import torch

from gen_tasks import NOVEL
from model import build


def logits_of(model, rows, device):
    xb = torch.from_numpy(rows["x_bytes"]).to(device)
    xh = torch.from_numpy(rows["x_hand"]).to(device)
    xhist = torch.from_numpy(rows["x_hist"]).to(device)
    out = []
    model.eval()
    with torch.no_grad():
        for i in range(0, len(xb), 2048):
            out.append(model(xb[i:i + 2048], xh[i:i + 2048], xhist[i:i + 2048]).float().cpu())
    return torch.cat(out).numpy()


def nll(z, y, t):
    z = z / t
    z = z - z.max(1, keepdims=True)
    logp = z - np.log(np.exp(z).sum(1, keepdims=True))
    return float(-logp[np.arange(len(y)), y].mean())


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True)
    ap.add_argument("--data", required=True)
    args = ap.parse_args()

    device = "cuda" if torch.cuda.is_available() else "cpu"
    ck = torch.load(args.model, map_location="cpu", weights_only=False)
    families = ck["families"]
    fam_to_idx = {f: i for i, f in enumerate(families)}
    model = build(ck["arch"], len(ck["features"]), len(families),
                  **(ck.get("kw") or {})).to(device)
    model.load_state_dict(ck["model"])

    d = np.load(args.data)
    rows = {k: d[k] for k in ("x_hand", "x_hist", "x_bytes", "family", "split")}

    def subset(part):
        m = rows["split"] == part
        return {k: v[m] for k, v in rows.items()}

    val = subset("val")
    novel = subset("novel")
    y_val = np.array([fam_to_idx[f] for f in val["family"] if f in fam_to_idx])
    keep = np.array([f in fam_to_idx for f in val["family"]])
    z_val = logits_of(model, {k: v[keep] for k, v in val.items()}, device)
    z_novel = logits_of(model, novel, device)

    grid = np.arange(0.5, 3.01, 0.05)
    losses = [nll(z_val, y_val, t) for t in grid]
    t_best = float(grid[int(np.argmin(losses))])
    print(f"[i] минимум NLL даёт T = {t_best:.2f} (это про уверенность на val, "
          f"не про честность на OOD)")

    def conf(z, t):
        z = z / t
        z = z - z.max(1, keepdims=True)
        e = np.exp(z)
        p = e / e.sum(1, keepdims=True)
        return float(p.max(1).mean()), float((p.max(1) < 0.5).mean()), \
            float((p.argmax(1) == y_val).mean()) if len(z) == len(y_val) else 0.0

    print("    T     OOD mean max   ниже 0.5   acc на val")
    for t in (0.6, 1.0, 1.5, 2.0, 2.5, 3.0):
        m, below, acc = conf(z_novel, t)
        print(f"    {t:3.1f}   {m:10.3f}   {below:7.0%}   {acc:.3f}")
    print("[+] для честности на незнакомом бери T, где OOD mean max ~0.5 "
          "(обычно 1.5–2.5)")


if __name__ == "__main__":
    main()
