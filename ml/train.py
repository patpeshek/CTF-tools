"""train.py — обучение роутера (decision model).

Пример:
  python ml/train.py --data F:\\AIproject\\ml-runs\\data_100k.npz --arch transformer \
      --epochs 25 --out F:\\AIproject\\ml-runs\\tf_100k.pt

Метрики печатаются по эпохам; в конце — OOD-проверка на семействах, которых
не было в обучении (модель должна сомневаться, а не врать).
"""
from __future__ import annotations

import argparse
import json
import math
import os
import time

import numpy as np
import torch
from torch import nn
from torch.utils.data import DataLoader, TensorDataset

from features import FEATURE_NAMES as DEFAULT_FEATURES
from gen_tasks import NOVEL
from model import build

try:
    from torch.utils.tensorboard import SummaryWriter
except Exception:  # tensorboard не обязателен
    SummaryWriter = None


def load(path, limit=0):
    d = np.load(path)
    n = len(d["y"])
    if limit and limit < n:
        n = limit
    return {k: d[k][:n] for k in ("x_hand", "x_hist", "x_bytes", "y", "family", "split")}


def tensors(rows, fam_to_idx=None):
    xb = torch.from_numpy(rows["x_bytes"])
    xh = torch.from_numpy(rows["x_hand"])
    xhist = torch.from_numpy(rows["x_hist"])
    if fam_to_idx is None:
        y = torch.zeros(len(rows["y"]), dtype=torch.long)
    else:
        y = torch.tensor([fam_to_idx.get(f, -1) for f in rows["family"]],
                         dtype=torch.long)
    return TensorDataset(xb, xh, xhist, y)


def evaluate(model, loader, device, n_classes):
    model.eval()
    correct = top2 = total = 0
    loss_sum = 0.0
    crit = nn.CrossEntropyLoss()
    with torch.no_grad():
        for xb, xh, xhist, y in loader:
            xb, xh, xhist, y = (t.to(device) for t in (xb, xh, xhist, y))
            with torch.amp.autocast("cuda", dtype=torch.bfloat16):
                logits = model(xb, xh, xhist)
                loss = crit(logits.float(), y)
            loss_sum += loss.item() * len(y)
            total += len(y)
            pred = logits.argmax(1)
            correct += (pred == y).sum().item()
            top = logits.topk(min(2, n_classes), dim=1).indices
            top2 += (top == y.unsqueeze(1)).any(1).sum().item()
    return loss_sum / max(1, total), correct / max(1, total), top2 / max(1, total)


def sample_probs(model, rows, idxs, device, families, top=3):
    """Вероятности по нескольким примерам — «как модель думает»."""
    xb = torch.from_numpy(rows["x_bytes"][idxs]).to(device)
    xh = torch.from_numpy(rows["x_hand"][idxs]).to(device)
    xhist = torch.from_numpy(rows["x_hist"][idxs]).to(device)
    model.eval()
    with torch.no_grad():
        with torch.amp.autocast("cuda", dtype=torch.bfloat16):
            probs = torch.softmax(model(xb, xh, xhist).float(), dim=1)
    out = []
    for i, idx in enumerate(idxs):
        p = probs[i]
        topv, topi = p.topk(min(top, len(families)))
        out.append({
            "true": str(rows["family"][idx]),
            "preds": [{"family": families[j], "p": round(float(v), 4)}
                      for v, j in zip(topv, topi)],
        })
    return out


def confusion(model, loader, device, n_classes):
    cm = np.zeros((n_classes, n_classes), dtype=np.int64)
    model.eval()
    with torch.no_grad():
        for xb, xh, xhist, y in loader:
            xb, xh, xhist = (t.to(device) for t in (xb, xh, xhist))
            with torch.amp.autocast("cuda", dtype=torch.bfloat16):
                pred = model(xb, xh, xhist).argmax(1).cpu().numpy()
            for t, p in zip(y.numpy(), pred):
                cm[t, p] += 1
    return cm


def ood_report(model, rows, device):
    xb, xh, xhist = (torch.from_numpy(rows[k]).to(device)
                     for k in ("x_bytes", "x_hand", "x_hist"))
    model.eval()
    with torch.no_grad():
        with torch.amp.autocast("cuda", dtype=torch.bfloat16):
            probs = torch.softmax(model(xb, xh, xhist).float(), dim=1)
    maxp = probs.max(1).values
    ent = -(probs * (probs + 1e-9).log()).sum(1)
    return {
        "n": int(len(maxp)),
        "mean_max_prob": round(float(maxp.mean()), 3),
        "median_max_prob": round(float(maxp.median()), 3),
        "share_below_0.5": round(float((maxp < 0.5).float().mean()), 3),
        "mean_entropy": round(float(ent.mean()), 3),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", required=True)
    ap.add_argument("--arch", default="transformer", choices=["mlp", "transformer"])
    ap.add_argument("--epochs", type=int, default=25)
    ap.add_argument("--batch", type=int, default=512)
    ap.add_argument("--lr", type=float, default=3e-4)
    ap.add_argument("--out", required=True)
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--dim", type=int, default=128)
    ap.add_argument("--hidden", type=int, default=256,
                    help="ширина MLP-роутера")
    ap.add_argument("--depth", type=int, default=2,
                    help="сколько слоёв в MLP (2 = как раньше)")
    ap.add_argument("--layers", type=int, default=4)
    ap.add_argument("--heads", type=int, default=4)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--class-weights", action="store_true",
                    help="взвесить классы обратно частоте (для перекошенных наборов)")
    ap.add_argument("--features-module", default="features",
                    help="modules with FEATURE_NAMES (для реверса: rev_features)")
    args = ap.parse_args()

    torch.manual_seed(args.seed)
    np.random.seed(args.seed)
    device = "cuda" if torch.cuda.is_available() else "cpu"
    print(f"[+] устройство: {device}", flush=True)

    import importlib
    feat = importlib.import_module(args.features_module)
    FEATURE_NAMES = feat.FEATURE_NAMES

    rows = load(args.data, args.limit)
    families = sorted({f for f in rows["family"] if f not in NOVEL})
    fam_to_idx = {f: i for i, f in enumerate(families)}
    n_classes = len(families)
    print(f"[+] классов: {n_classes} ({', '.join(families)})", flush=True)

    def mask(part):
        return rows["split"] == part

    def subset(part):
        return {k: v[mask(part)] for k, v in rows.items()}

    train_rows, val_rows, test_rows = subset("train"), subset("val"), subset("test")
    novel_rows = subset("novel")
    print(f"[+] train={len(train_rows['y'])} val={len(val_rows['y'])} "
          f"test={len(test_rows['y'])} novel={len(novel_rows['y'])}", flush=True)

    dl = lambda tds, shuffle: DataLoader(tds, batch_size=args.batch, shuffle=shuffle,
                                         num_workers=0, drop_last=False)
    train_dl = dl(tensors(train_rows, fam_to_idx), True)
    val_dl = dl(tensors(val_rows, fam_to_idx), False)
    test_dl = dl(tensors(test_rows, fam_to_idx), False)

    model = build(args.arch, len(FEATURE_NAMES), n_classes, dim=args.dim,
                  layers=args.layers, heads=args.heads,
                  hidden=args.hidden, depth=args.depth).to(device)
    n_params = sum(p.numel() for p in model.parameters())
    print(f"[+] параметров: {n_params:,}", flush=True)
    opt = torch.optim.AdamW(model.parameters(), lr=args.lr, weight_decay=0.01)
    steps = max(1, len(train_dl) * args.epochs)
    sched = torch.optim.lr_scheduler.OneCycleLR(
        opt, max_lr=args.lr, total_steps=steps, pct_start=0.1)
    if args.class_weights:
        counts = np.bincount([fam_to_idx.get(f, 0) for f in train_rows["family"]],
                             minlength=n_classes).astype(np.float64)
        w = np.sqrt(counts.sum() / (n_classes * np.maximum(counts, 1.0)))
        w = np.clip(w, 0.5, 4.0)      # жёсткие веса ломают большинство
        crit = nn.CrossEntropyLoss(
            weight=torch.tensor(w, dtype=torch.float32).to(device),
            label_smoothing=0.05)
        print("[+] веса классов: " + ", ".join(f"{f}={v:.2f}" for f, v in
                                              zip(families, w)), flush=True)
    else:
        crit = nn.CrossEntropyLoss(label_smoothing=0.05)

    best = -1.0
    history = []
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    base_out = os.path.splitext(args.out)[0]
    log_path = base_out + ".jsonl"
    writer = SummaryWriter(log_dir=base_out + "_tb") if SummaryWriter else None
    sample_idx = list(range(min(3, len(val_rows["y"]))))
    for epoch in range(1, args.epochs + 1):
        model.train()
        t0 = time.time()
        run_loss = seen = 0
        for xb, xh, xhist, y in train_dl:
            xb, xh, xhist, y = (t.to(device) for t in (xb, xh, xhist, y))
            opt.zero_grad(set_to_none=True)
            with torch.amp.autocast("cuda", dtype=torch.bfloat16):
                logits = model(xb, xh, xhist)
                loss = crit(logits.float(), y)
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            opt.step()
            sched.step()
            run_loss += loss.item() * len(y)
            seen += len(y)
        val_loss, val_acc, val_top2 = evaluate(model, val_dl, device, n_classes)
        row = {"epoch": epoch, "train_loss": round(run_loss / max(1, seen), 4),
               "val_loss": round(val_loss, 4), "val_acc": round(val_acc, 4),
               "val_top2": round(val_top2, 4), "lr": round(sched.get_last_lr()[0], 6),
               "sec": round(time.time() - t0, 1)}
        history.append(row)
        print("[{epoch:02d}] loss={train_loss:.3f} val={val_loss:.3f} "
              "acc={val_acc:.3f} top2={val_top2:.3f} {sec}s".format(**row), flush=True)
        samples = sample_probs(model, val_rows, sample_idx, device, families)
        for s in samples:
            top = " | ".join(f"{x['family']} {x['p']:.2f}" for x in s["preds"])
            print(f"    думаю: true={s['true']} → {top}", flush=True)
        with open(log_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps({"type": "epoch", **row, "samples": samples},
                                ensure_ascii=False) + "\n")
        if writer:
            writer.add_scalar("loss/train", row["train_loss"], epoch)
            writer.add_scalar("loss/val", row["val_loss"], epoch)
            writer.add_scalar("acc/val", row["val_acc"], epoch)
            writer.add_scalar("acc/top2", row["val_top2"], epoch)
            writer.add_scalar("lr", row["lr"], epoch)
            writer.flush()
        if val_acc > best:
            best = val_acc
            torch.save({"model": model.state_dict(), "arch": args.arch,
                        "families": families, "features": FEATURE_NAMES,
                        "kw": {"dim": args.dim, "layers": args.layers,
                               "heads": args.heads,
                               "hidden": args.hidden, "depth": args.depth}}, args.out)
            print(f"    [+] сохранено (best val_acc={best:.3f}) → {args.out}",
                  flush=True)

    saved = torch.load(args.out, weights_only=False)
    model.load_state_dict(saved["model"])
    test_loss, test_acc, test_top2 = evaluate(model, test_dl, device, n_classes)
    ood = ood_report(model, novel_rows, device) if len(novel_rows["y"]) else {}
    tl, ta, t2 = test_loss, test_acc, test_top2
    print(f"[=] test acc={test_acc:.3f} top2={test_top2:.3f} loss={test_loss:.3f}",
          flush=True)
    cm = confusion(model, test_dl, device, n_classes)
    print("[=] по классам:", flush=True)
    for i, fam in enumerate(families):
        n_i = int(cm[i].sum())
        print(f"    {fam:12s} acc={cm[i, i] / max(1, n_i):.3f} (n={n_i})", flush=True)
    off = sorted(((int(cm[i, j]), families[i], families[j])
                  for i in range(n_classes) for j in range(n_classes) if i != j),
                 reverse=True)[:3]
    print("    частые ошибки: " + ", ".join(f"{a}→{b} ({n})" for n, a, b in off),
          flush=True)
    if ood:
        print(f"[=] OOD (невиданные семейства): {ood}", flush=True)
    meta = {"arch": args.arch, "params": n_params, "families": families,
            "features": FEATURE_NAMES, "history": history, "best_val_acc": best,
            "test": {"acc": test_acc, "top2": test_top2, "loss": test_loss},
            "ood": ood, "confusion": cm.tolist(), "data": os.path.abspath(args.data)}
    with open(os.path.splitext(args.out)[0] + ".json", "w", encoding="utf-8") as fh:
        json.dump(meta, fh, ensure_ascii=False, indent=1)
    with open(log_path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps({"type": "final", "test": meta["test"],
                             "ood": ood, "confusion": cm.tolist()},
                            ensure_ascii=False) + "\n")
    if writer:
        writer.close()
    print("[+] метрики: " + os.path.splitext(args.out)[0] + ".json", flush=True)


if __name__ == "__main__":
    main()
