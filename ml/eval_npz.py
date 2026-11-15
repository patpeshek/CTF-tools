"""eval_npz.py — быстрый замер модели по датасету из npz (синтетика или реальные).

Нужен, чтобы сравнивать модели на одном и том же наборе без чтения файлов:
`realdata.py` сохраняет настоящие артефакты в ту же форму, что `gen_tasks.py`.

  python ml/eval_npz.py --model F:\\AIproject\\ml-runs\\mlp_v7.pt ^
      --npz F:\\AIproject\\ml-runs\\real_v1.npz
"""
from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import numpy as np
import torch

import importlib

from model import build


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True)
    ap.add_argument("--npz", required=True)
    ap.add_argument("--split", default="")
    ap.add_argument("--top", type=int, default=3)
    ap.add_argument("--features-module", default="features")
    args = ap.parse_args()

    ck = torch.load(args.model, map_location="cpu", weights_only=False)
    feat = importlib.import_module(args.features_module)
    FEATURE_NAMES = feat.FEATURE_NAMES
    if len(ck["features"]) != len(FEATURE_NAMES):
        raise SystemExit(
            f"[-] чекпоинт на {len(ck['features'])} признаках, features.py даёт "
            f"{len(FEATURE_NAMES)} — модели несовместимы")
    families = ck["families"]
    model = build(ck["arch"], len(ck["features"]), len(families), **(ck.get("kw") or {}))
    model.load_state_dict(ck["model"])
    model.eval()

    d = np.load(args.npz)
    mask = np.ones(len(d["y"]) if "y" in d.files else len(d["family"]), bool)
    if args.split and "split" in d.files:
        mask = d["split"] == args.split
    xh = torch.from_numpy(d["x_hand"][mask])
    xhist = torch.from_numpy(d["x_hist"][mask])
    xb = torch.from_numpy(d["x_bytes"][mask])
    fam = d["family"][mask]
    with torch.no_grad():
        logits = model(xb, xh, xhist)
        probs = torch.softmax(logits.float(), dim=1).numpy()

    ok = total = 0
    per = {}
    confusions = {}
    for i, true in enumerate(fam):
        total += 1
        if true not in families:
            continue
        pred = families[int(probs[i].argmax())]
        good = pred == true
        ok += good
        per.setdefault(true, [0, 0])
        per[true][0] += good
        per[true][1] += 1
        if not good:
            confusions[(true, pred)] = confusions.get((true, pred), 0) + 1

    print(f"[+] примеров: {total}, оценено: {sum(v[1] for v in per.values())}")
    print(f"[=] точность: {ok}/{sum(v[1] for v in per.values())}")
    print("[=] по семействам:")
    for name, (good, n) in sorted(per.items(), key=lambda kv: kv[1][0] / kv[1][1]):
        print(f"    {name:12s} {good}/{n}")
    if confusions:
        top = sorted(confusions.items(), key=lambda kv: -kv[1])[:10]
        print("[=] путаница: " + ", ".join(f"{a}→{b}×{n}" for (a, b), n in top))
    unknown = [str(f) for f in fam if f not in families]
    if unknown:
        print(f"[i] меток вне словаря модели: {len(unknown)} "
              f"({', '.join(sorted(set(unknown))[:6])})")


if __name__ == "__main__":
    main()
