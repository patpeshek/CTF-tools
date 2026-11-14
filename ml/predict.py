"""predict.py — что локальная модель думает про файл или строку.

  python ml/predict.py --model F:\\AIproject\\ml-runs\\mlp_100k.pt --file chall.bin
  python ml/predict.py --model ... --text "aGVsbG8gd29ybGQ="

Печатает top-5 семейств с вероятностями и честно говорит «не уверен», если
максимум ниже порога. Это decision model: только вероятности, без генерации.
"""
from __future__ import annotations

import argparse
import sys

import torch

from features import FEATURE_NAMES, byte_hist, byte_ids, hand_features
from model import build

CONF = {i: name for i, name in enumerate(FEATURE_NAMES)}


def top_features(x, k=8):
    """Какие признаки сильнее всего отклонились от среднего (грубо, для глаз)."""
    import numpy as np
    x = np.asarray(x)
    return sorted(((abs(float(v)), name, float(v))
                   for v, name in zip(x, FEATURE_NAMES)), reverse=True)[:k]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True)
    ap.add_argument("--file")
    ap.add_argument("--text")
    ap.add_argument("--top", type=int, default=5)
    ap.add_argument("--threshold", type=float, default=0.5)
    args = ap.parse_args()
    if args.file:
        data = open(args.file, "rb").read()
    elif args.text is not None:
        data = args.text.encode()
    else:
        data = sys.stdin.buffer.read()

    ck = torch.load(args.model, map_location="cpu", weights_only=False)
    families = ck["families"]
    kw = ck.get("kw") or {}
    model = build(ck["arch"], len(ck["features"]), len(families), **kw)
    model.load_state_dict(ck["model"])
    model.eval()

    xb = torch.from_numpy(byte_ids(data)).unsqueeze(0)
    xh = torch.from_numpy(hand_features(data)).unsqueeze(0)
    xhist = torch.from_numpy(byte_hist(data)).unsqueeze(0)
    with torch.no_grad():
        probs = torch.softmax(model(xb, xh, xhist).float(), dim=1)[0]
    vals, idx = probs.topk(min(args.top, len(families)))
    print(f"[+] размер: {len(data)} байт")
    print("[+] вероятности:")
    for v, i in zip(vals.tolist(), idx.tolist()):
        bar = "█" * max(0, int(v * 30))
        print(f"    {families[i]:12s} {v:5.2f}  {bar}")
    best = float(vals[0]) if len(vals) else 0.0
    print("[+] вердикт:", "уверен" if best >= args.threshold
          else f"НЕ уверен (max={best:.2f} < {args.threshold}) — лучше спросить человека")
    print("[+] признаки, которые сильнее всего повлияли (эвристика):")
    for val, name, raw in top_features(hand_features(data)):
        print(f"    {name:14s} {raw: .3f}")


if __name__ == "__main__":
    main()
