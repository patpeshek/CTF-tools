"""train_hf.py — дообучение готового текстового энкодера как decision model.

Это тот самый вариант «скачать готовое и переобучить»: берём маленький
pretrained-энкодер, ставим классификационную голову и учим выбирать семейство
по тексту задачи/артефакта. Модель выдаёт вероятности, ничего не генерирует.

Требуется (один раз):
  F:\\ml\\gdrl\\python\\venv\\Scripts\\pip install transformers accelerate

Пример:
  python ml/train_hf.py --data F:\\AIproject\\ml-runs\\data_100k.npz \
      --model microsoft/deberta-v3-small --epochs 4 \
      --out F:\\AIproject\\ml-runs\\hf_deberta
"""
from __future__ import annotations

import argparse
import json
import os
import time

import numpy as np
import torch
from torch.utils.data import DataLoader, Dataset
from transformers import (AutoModelForSequenceClassification, AutoTokenizer,
                          get_linear_schedule_with_warmup)

from gen_tasks import NOVEL


class TextDS(Dataset):
    def __init__(self, rows, fam_to_idx=None):
        self.texts = rows["text"].tolist()
        if fam_to_idx is None:
            self.labels = [-1] * len(self.texts)
        else:
            self.labels = [fam_to_idx.get(f, -1) for f in rows["family"]]

    def __len__(self):
        return len(self.texts)

    def __getitem__(self, i):
        return self.texts[i], self.labels[i]


def collate(batch, tok, max_len):
    texts = [b[0] for b in batch]
    enc = tok(texts, truncation=True, max_length=max_len, padding=True,
              return_tensors="pt")
    enc["labels"] = torch.tensor([b[1] for b in batch], dtype=torch.long)
    return enc


def evaluate(model, loader, device):
    model.eval()
    loss_sum = correct = top2 = total = 0
    with torch.no_grad():
        for batch in loader:
            batch = {k: v.to(device) for k, v in batch.items()}
            with torch.amp.autocast("cuda", dtype=torch.bfloat16):
                out = model(**batch)
            logits = out.logits.float()
            loss_sum += out.loss.item() * len(batch["labels"])
            total += len(batch["labels"])
            correct += (logits.argmax(1) == batch["labels"]).sum().item()
            top = logits.topk(2, dim=1).indices
            top2 += (top == batch["labels"].unsqueeze(1)).any(1).sum().item()
    return loss_sum / max(1, total), correct / max(1, total), top2 / max(1, total)


def ood(model, loader, device):
    model.eval()
    maxp, ent = [], []
    with torch.no_grad():
        for batch in loader:
            batch = {k: v.to(device) for k, v in batch.items()}
            with torch.amp.autocast("cuda", dtype=torch.bfloat16):
                probs = torch.softmax(model(**batch).logits.float(), dim=1)
            maxp.append(probs.max(1).values.cpu())
            ent.append(-(probs * (probs + 1e-9).log()).sum(1).cpu())
    if not maxp:
        return {}
    maxp = torch.cat(maxp)
    ent = torch.cat(ent)
    return {"n": int(len(maxp)),
            "mean_max_prob": round(float(maxp.mean()), 3),
            "share_below_0.5": round(float((maxp < 0.5).float().mean()), 3),
            "mean_entropy": round(float(ent.mean()), 3)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", required=True)
    ap.add_argument("--model", default="microsoft/deberta-v3-small")
    ap.add_argument("--epochs", type=int, default=4)
    ap.add_argument("--batch", type=int, default=32)
    ap.add_argument("--lr", type=float, default=3e-5)
    ap.add_argument("--max-len", type=int, default=256)
    ap.add_argument("--out", required=True)
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--freeze", type=int, default=0,
                    help="заморозить первые N слоёв энкодера")
    args = ap.parse_args()

    device = "cuda" if torch.cuda.is_available() else "cpu"
    d = np.load(args.data)
    n = len(d["y"])
    if args.limit and args.limit < n:
        n = args.limit
    rows = {k: d[k][:n] for k in d.files}
    families = sorted({f for f in rows["family"] if f not in NOVEL})
    fam_to_idx = {f: i for i, f in enumerate(families)}
    print(f"[+] классов: {len(families)}; устройство: {device}", flush=True)

    def subset(part):
        m = rows["split"] == part
        return {k: v[m] for k, v in rows.items()}

    tr, va, te, no = (subset(x) for x in ("train", "val", "test", "novel"))
    tok = AutoTokenizer.from_pretrained(args.model)
    model = AutoModelForSequenceClassification.from_pretrained(
        args.model, num_labels=len(families)).to(device)
    if args.freeze:
        base = getattr(model, model.base_model_prefix, None)
        if base is not None:
            for i, layer in enumerate(base.encoder.layer):
                if i < args.freeze:
                    for p in layer.parameters():
                        p.requires_grad = False
            print(f"[+] заморожено слоёв: {args.freeze}", flush=True)

    def dl(part, shuffle):
        return DataLoader(TextDS(part, fam_to_idx), batch_size=args.batch,
                          shuffle=shuffle, num_workers=0,
                          collate_fn=lambda b: collate(b, tok, args.max_len))

    train_dl = dl(tr, True)
    val_dl = dl(va, False)
    test_dl = dl(te, False)
    novel_dl = dl(no, False)
    if len(tr["y"]) == 0:
        print("[-] нет train-примеров", flush=True)
        return

    opt = torch.optim.AdamW([p for p in model.parameters() if p.requires_grad],
                            lr=args.lr, weight_decay=0.01)
    steps = max(1, len(train_dl) * args.epochs)
    sched = get_linear_schedule_with_warmup(opt, int(steps * 0.1), steps)
    best, hist = -1.0, []
    os.makedirs(args.out, exist_ok=True)
    for ep in range(1, args.epochs + 1):
        model.train()
        t0 = time.time()
        run = seen = 0
        for batch in train_dl:
            batch = {k: v.to(device) for k, v in batch.items()}
            opt.zero_grad(set_to_none=True)
            with torch.amp.autocast("cuda", dtype=torch.bfloat16):
                out = model(**batch)
            out.loss.backward()
            torch.nn.utils.clip_grad_norm_(
                [p for p in model.parameters() if p.requires_grad], 1.0)
            opt.step()
            sched.step()
            run += out.loss.item() * len(batch["labels"])
            seen += len(batch["labels"])
        vl, va_acc, va_top2 = evaluate(model, val_dl, device)
        row = {"epoch": ep, "train_loss": round(run / max(1, seen), 4),
               "val_loss": round(vl, 4), "val_acc": round(va_acc, 4),
               "val_top2": round(va_top2, 4), "sec": round(time.time() - t0, 1)}
        hist.append(row)
        print("[{epoch:02d}] loss={train_loss:.3f} val={val_loss:.3f} "
              "acc={val_acc:.3f} top2={val_top2:.3f} {sec}s".format(**row),
              flush=True)
        if va_acc > best:
            best = va_acc
            model.save_pretrained(args.out)
            tok.save_pretrained(args.out)
            print(f"    [+] сохранено (val_acc={best:.3f}) → {args.out}", flush=True)

    tl, ta, t2 = evaluate(model, test_dl, device)
    oo = ood(model, novel_dl, device)
    print(f"[=] test acc={ta:.3f} top2={t2:.3f}", flush=True)
    if oo:
        print(f"[=] OOD: {oo}", flush=True)
    meta = {"model": args.model, "families": families, "history": hist,
            "test": {"acc": ta, "top2": t2, "loss": tl}, "ood": oo,
            "data": os.path.abspath(args.data)}
    with open(os.path.join(args.out, "metrics.json"), "w", encoding="utf-8") as f:
        json.dump(meta, f, ensure_ascii=False, indent=1)


if __name__ == "__main__":
    main()
