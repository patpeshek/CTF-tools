"""error_report.py — какие ошибки делает модель и на каких файлах.

Гадать «почему 93.6%, а не 99%» бессмысленно: нужно видеть конкретные пары
(что предсказали вместо чего) и сами файлы. Скрипт печатает топ путаниц с
примерами путей и превью первых байт — по ним видно, это ошибка модели или
ошибка разметки.

  python ml/error_report.py --model ...\\mlp_v13_mix.pt --npz ...\\real_archive.npz
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


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True)
    ap.add_argument("--npz", required=True)
    ap.add_argument("--holdout", type=int, default=5,
                    help="каждый N-й по хешу — отложенный (как во finetune_real)")
    ap.add_argument("--pair", default="", help="показать только пару true→pred")
    ap.add_argument("--limit", type=int, default=6, help="примеров на пару")
    args = ap.parse_args()

    ck = torch.load(args.model, map_location="cpu", weights_only=False)
    families = ck["families"]
    model = build(ck["arch"], len(ck["features"]), len(families),
                  **(ck.get("kw") or {}))
    model.load_state_dict(ck["model"])
    model.eval()

    d = np.load(args.npz)
    if "digest" in d.files and args.holdout:
        idx = np.array([i for i, h in enumerate(d["digest"])
                        if int(h[:4], 16) % args.holdout == 0])
    else:
        idx = np.arange(len(d["family"]))
    print(f"[+] проверяем {len(idx)} файлов (отложенная часть)")

    with torch.no_grad():
        logits = []
        for i in range(0, len(idx), 1024):
            j = idx[i:i + 1024]
            logits.append(model(torch.from_numpy(d["x_bytes"][j]),
                                torch.from_numpy(d["x_hand"][j]),
                                torch.from_numpy(d["x_hist"][j])).float())
        probs = torch.softmax(torch.cat(logits), dim=1).numpy()

    fam = d["family"][idx]
    pred = np.array(families)[probs.argmax(1)]
    paths = d["path"][idx] if "path" in d.files else np.array([""] * len(idx))
    known = np.array([f in families for f in fam])
    acc = float((pred[known] == fam[known]).mean()) if known.any() else 0.0
    print(f"[=] точность: {acc:.4f} на {int(known.sum())} размеченных")

    pairs = {}
    for i in np.where(known & (pred != fam))[0]:
        pairs.setdefault((str(fam[i]), str(pred[i])), []).append(i)
    print(f"[=] всего ошибок: {sum(len(v) for v in pairs.values())}")
    print("[=] топ путаниц:")
    for (t, p), items in sorted(pairs.items(), key=lambda kv: -len(kv[1]))[:12]:
        print(f"    {t:12s} → {p:12s} {len(items):4d}")

    for (t, p), items in sorted(pairs.items(), key=lambda kv: -len(kv[1])):
        if args.pair and f"{t}→{p}" != args.pair.replace(" ", ""):
            continue
        print(f"\n=== {t} → {p} ({len(items)}) ===")
        for i in items[:args.limit]:
            path = str(paths[i])
            conf = float(probs[i].max())
            print(f"  {os.path.basename(path)[:48]:50s} p={conf:.2f}")
            try:
                with open(path, "rb") as fh:
                    head = fh.read(96)
                txt = "".join(c if 32 <= ord(c) < 127 else "." for c in
                              head.decode("latin-1"))
                print(f"      {txt[:88]}")
            except OSError:
                print("      (файл недоступен)")


if __name__ == "__main__":
    main()
