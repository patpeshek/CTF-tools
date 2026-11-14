"""train_policy.py — модель «какой инструмент сработает» на трассах солвера.

В отличие от роутера (он говорит, что за файл), эта модель отвечает на вопрос
политики: **что делать следующим**. Вход — состояние задачи (признаки файла)
+ инструмент; выход — вероятность, что этот инструмент даст флаг.

Метрика тоже другая: не accuracy, а **MRR и top-3** — попал ли успешный
инструмент в тройку лучших по оценке модели, и на каком месте.

  python ml/train_policy.py --data F:\\...\\policy_v1.npz
"""
from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import numpy as np
import torch
from torch import nn


def auc(scores: np.ndarray, labels: np.ndarray) -> float:
    """Площадь под ROC без sklearn: ранговая формула Манна–Уитни."""
    order = np.argsort(scores)
    ranks = np.empty(len(scores), dtype=np.float64)
    ranks[order] = np.arange(1, len(scores) + 1)
    pos = labels == 1
    n_pos, n_neg = int(pos.sum()), int((~pos).sum())
    if not n_pos or not n_neg:
        return 0.0
    return float((ranks[pos].sum() - n_pos * (n_pos + 1) / 2) / (n_pos * n_neg))


class Policy(nn.Module):
    def __init__(self, n_in: int, hidden: int = 256):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(n_in, hidden), nn.GELU(), nn.Dropout(0.2),
            nn.Linear(hidden, hidden // 2), nn.GELU(),
            nn.Linear(hidden // 2, 1),
        )

    def forward(self, x):
        return self.net(x).squeeze(1)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", required=True)
    ap.add_argument("--epochs", type=int, default=40)
    ap.add_argument("--lr", type=float, default=1e-3)
    ap.add_argument("--out", default="")
    ap.add_argument("--seed", type=int, default=1)
    args = ap.parse_args()

    d = np.load(args.data, allow_pickle=True)
    X, y, groups = d["X"], d["y"], d["groups"]
    tools = [str(t) for t in d["tools"]]
    n_tools = len(tools)

    # делим по задачам, а не по шагам: иначе утечка одинаковых состояний
    uniq = np.unique(groups)
    rng = np.random.default_rng(args.seed)
    rng.shuffle(uniq)
    cut = int(len(uniq) * 0.8)
    train_g, test_g = set(uniq[:cut].tolist()), set(uniq[cut:].tolist())
    tr = np.array([g in train_g for g in groups])
    te = ~tr
    print(f"[+] задач: {len(uniq)} (train {cut}, test {len(uniq) - cut}); "
          f"шагов: train {tr.sum()}, test {te.sum()}")
    print(f"[+] успешных шагов: {y.mean():.3%}")

    device = "cuda" if torch.cuda.is_available() else "cpu"
    model = Policy(X.shape[1]).to(device)
    opt = torch.optim.AdamW(model.parameters(), lr=args.lr, weight_decay=1e-2)
    # классы сильно несбалансированы: без веса модель просто скажет «нет»
    pos_weight = torch.tensor([(1 - y[tr].mean()) / max(1e-6, y[tr].mean())],
                              device=device)
    crit = nn.BCEWithLogitsLoss(pos_weight=pos_weight)
    xb = torch.from_numpy(X[tr]).to(device)
    yb = torch.from_numpy(y[tr]).to(device)
    bs = 512
    for ep in range(args.epochs):
        model.train()
        perm = torch.randperm(len(xb), device=device)
        total = 0.0
        for i in range(0, len(xb), bs):
            idx = perm[i:i + bs]
            opt.zero_grad(set_to_none=True)
            loss = crit(model(xb[idx]), yb[idx])
            loss.backward()
            opt.step()
            total += loss.item() * len(idx)
        if ep % 5 == 4 or ep == args.epochs - 1:
            print(f"    эпоха {ep + 1}: loss={total / len(xb):.4f}", flush=True)

    model.eval()
    with torch.no_grad():
        p_tr = torch.sigmoid(model(torch.from_numpy(X[tr]).to(device))).cpu().numpy()
        p_te = torch.sigmoid(model(torch.from_numpy(X[te]).to(device))).cpu().numpy()
    print(f"[=] AUC train={auc(p_tr, y[tr]):.3f}  test={auc(p_te, y[te]):.3f}")

    # ранжирование по задачам: успешный инструмент должен быть высоко
    ranks, hits3, hits1 = [], 0, 0
    for g in sorted(test_g):
        mask = groups[te] == g if False else None  # noqa: F841 (заглушка)
    test_idx = np.where(te)[0]
    by_task = {}
    for i in test_idx:
        by_task.setdefault(int(groups[i]), []).append(i)
    for g, idxs in by_task.items():
        good = [i for i in idxs if y[i] == 1]
        if not good:
            continue
        order = sorted(idxs, key=lambda i: -p_te[np.searchsorted(test_idx, i)])
        rank = next((k + 1 for k, i in enumerate(order) if y[i] == 1), None)
        if rank is None:
            continue
        ranks.append(rank)
        hits1 += rank == 1
        hits3 += rank <= 3
    if ranks:
        print(f"[=] ранжирование по задачам (n={len(ranks)}): "
              f"top-1 {hits1 / len(ranks):.2f}, top-3 {hits3 / len(ranks):.2f}, "
              f"MRR {np.mean([1 / r for r in ranks]):.3f}")

    if args.out:
        torch.save({"model": model.state_dict(), "n_in": X.shape[1],
                    "tools": tools, "hidden": 256}, args.out)
        print(f"[+] сохранено → {args.out}")


if __name__ == "__main__":
    main()
