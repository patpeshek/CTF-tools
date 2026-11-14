"""finetune_real.py — проверяемый эксперимент: даёт ли дообучение на настоящих
файлах выигрыш на настоящих файлах и не портит ли синтетику.

Идея: синтетика учит правилам, но живёт в своём распределении. Настоящих
файлов мало (сотни), поэтому их нельзя просто добавить в 100k — утонут.
Делаем так:

  1. реальные файлы (`realdata.py`) делятся на `train`/`test` по хешу имени,
     чтобы тест никогда не пересекался с обучением;
  2. базовая модель учится на синтетике;
  3. её дообучают на реальном train (с повтором, чтобы вес был заметен);
  4. обе модели меряются на реальном тесте и на синтетическом тесте.

Печатается таблица «до/после» по обоим наборам — если синтетика проседает
сильнее, чем растёт реальный тест, датасет плохой и это видно сразу.

  python ml/finetune_real.py --syn F:\\AIproject\\ml-runs\\data_v8_100k.npz ^
      --real F:\\AIproject\\ml-runs\\real_v1.npz --epochs 6 --repeat 12
"""
from __future__ import annotations

import argparse
import hashlib
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import numpy as np
import torch
from torch.utils.data import DataLoader, TensorDataset

from features import FEATURE_NAMES
from model import build
from train import evaluate


def masks(d, part):
    return d["split"] == part


def pack(d, idx):
    xb = torch.from_numpy(d["x_bytes"][idx])
    xh = torch.from_numpy(d["x_hand"][idx])
    xhist = torch.from_numpy(d["x_hist"][idx])
    return xb, xh, xhist


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--syn", required=True)
    ap.add_argument("--real", required=True)
    ap.add_argument("--epochs", type=int, default=6)
    ap.add_argument("--repeat", type=int, default=12,
                    help="сколько раз повторить реальный train за эпоху")
    ap.add_argument("--lr", type=float, default=1e-4)
    ap.add_argument("--batch", type=int, default=256)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--replay-syn", action="store_true",
                    help="в каждой эпохе дообучения прогнать синтетику — "
                         "чтобы не забыть основную задачу")
    ap.add_argument("--out", default="")
    args = ap.parse_args()

    torch.manual_seed(args.seed)
    np.random.seed(args.seed)
    device = "cuda" if torch.cuda.is_available() else "cpu"

    syn = np.load(args.syn)
    real = np.load(args.real)
    if len(real["x_hand"][0]) != len(FEATURE_NAMES):
        raise SystemExit("[-] реальные данные собраны другой версией features.py")

    families = sorted({f for f in syn["family"]} - {"b32", "utf16"})
    fam_to_idx = {f: i for i, f in enumerate(families)}
    n_classes = len(families)

    # реальные делим по хешу: тест не пересекается с train
    digests = real["digest"]
    is_test = np.array([int(h[:4], 16) % 5 == 0 for h in digests])
    r_train = np.where(~is_test)[0]
    r_test = np.where(is_test)[0]
    print(f"[+] классов: {n_classes}; реальных: train={len(r_train)} "
          f"test={len(r_test)}", flush=True)
    lab = {str(f) for f in real["family"]}
    print(f"[+] реальные семейства в словаре модели: "
          f"{len(lab & set(families))}/{len(lab)}", flush=True)

    def dl(idx, d, shuffle):
        xb, xh, xhist = pack(d, idx)
        y = torch.tensor([fam_to_idx.get(f, -1) for f in d["family"][idx]],
                         dtype=torch.long)
        keep = y >= 0
        tds = TensorDataset(xb[keep], xh[keep], xhist[keep], y[keep])
        return DataLoader(tds, batch_size=args.batch, shuffle=shuffle, num_workers=0)

    tr_idx = np.where(masks(syn, "train"))[0]
    va_idx = np.where(masks(syn, "val"))[0]
    te_idx = np.where(masks(syn, "test"))[0]
    syn_tr = dl(tr_idx, syn, True)
    syn_va = dl(va_idx, syn, False)
    syn_te = dl(te_idx, syn, False)
    real_te = dl(r_test, real, False)

    model = build("mlp", len(FEATURE_NAMES), n_classes).to(device)
    opt = torch.optim.AdamW(model.parameters(), lr=args.lr, weight_decay=0.01)
    crit = torch.nn.CrossEntropyLoss(label_smoothing=0.05)

    def report(tag):
        _, sa, _ = evaluate(model, syn_te, device, n_classes)
        _, ra, _ = evaluate(model, real_te, device, n_classes)
        print(f"[{tag}] синтетика test acc={sa:.3f} | реальные test acc={ra:.3f}",
              flush=True)
        return sa, ra

    # --- 1. базовая модель: только синтетика, 8 быстрых эпох
    for ep in range(8):
        model.train()
        for xb, xh, xhist, y in syn_tr:
            xb, xh, xhist, y = (t.to(device) for t in (xb, xh, xhist, y))
            opt.zero_grad(set_to_none=True)
            loss = crit(model(xb, xh, xhist), y)
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            opt.step()
        if ep % 2 == 1:
            _, va, _ = evaluate(model, syn_va, device, n_classes)
            print(f"    эпоха {ep + 1}: val={va:.3f}", flush=True)
    base = report("база")

    # --- 2. дообучение на реальном train
    real_tr = dl(r_train, real, True)
    t0 = time.time()
    for ep in range(args.epochs):
        model.train()
        for _ in range(args.repeat):
            for xb, xh, xhist, y in real_tr:
                xb, xh, xhist, y = (t.to(device) for t in (xb, xh, xhist, y))
                opt.zero_grad(set_to_none=True)
                loss = crit(model(xb, xh, xhist), y)
                loss.backward()
                torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
                opt.step()
        if args.replay_syn:
            # один проход по синтетике: без этого модель забывает основную
            # задачу (проверено: 0.992 → 0.739 за 6 эпох на реальных)
            for xb, xh, xhist, y in syn_tr:
                xb, xh, xhist, y = (t.to(device) for t in (xb, xh, xhist, y))
                opt.zero_grad(set_to_none=True)
                loss = crit(model(xb, xh, xhist), y)
                loss.backward()
                torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
                opt.step()
        print(f"    дообучение {ep + 1}/{args.epochs} ({time.time() - t0:.1f} c)",
              flush=True)
    after = report("после")

    print(flush=True)
    print(f"[=] синтетика: {base[0]:.3f} → {after[0]:.3f} "
          f"({after[0] - base[0]:+.3f})")
    print(f"[=] реальные:  {base[1]:.3f} → {after[1]:.3f} "
          f"({after[1] - base[1]:+.3f})")
    if args.out:
        torch.save({"model": model.state_dict(), "arch": "mlp",
                    "families": families, "features": FEATURE_NAMES}, args.out)
        print(f"[+] сохранено → {args.out}")


if __name__ == "__main__":
    main()
