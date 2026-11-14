"""eval_dir.py — что модель думает про реальные файлы из папки.

Синтетика — это только проверка пайплайна. Настоящая проверка — живые
артефакты: png, zip, pcap, txt. Скрипт проходит по папке, для каждого файла
печатает top-3 семейства с вероятностями и честно помечает «не уверен».

  python ml/eval_dir.py --model F:\\AIproject\\ml-runs\\hf_deberta ^
      --dir F:\\AIproject\\_scratch\\custom_tasks --min-size 32

Поддерживаются оба вида чекпоинтов:
  * папка с config.json — fine-tuned энкодер (train_hf.py);
  * *.pt — MLP/transformer (train.py).
"""
from __future__ import annotations

import argparse
import os

import numpy as np
import torch

from features import byte_hist, byte_ids, hand_features
from model import build


def load(path):
    """Возвращает (kind, predict_fn, threshold_hint)."""
    if os.path.isdir(path):
        from transformers import AutoModelForSequenceClassification, AutoTokenizer
        from train_hf import text_view
        ck = {}
        meta_path = os.path.join(path, "metrics.json")
        if os.path.exists(meta_path):
            import json
            with open(meta_path, encoding="utf-8") as fh:
                ck = json.load(fh)
        families = ck.get("families") or []
        view = ck.get("view", "meta")
        tok = AutoTokenizer.from_pretrained(path)
        model = AutoModelForSequenceClassification.from_pretrained(path).eval()
        if not families:
            families = [str(i) for i in range(model.config.num_labels)]

        def predict(data):
            text = text_view(data.decode("utf-8", "replace")) if view == "meta" \
                else data.decode("utf-8", "replace")
            enc = tok([text], truncation=True, max_length=256, return_tensors="pt")
            with torch.no_grad():
                probs = torch.softmax(model(**enc).logits.float(), dim=1)[0]
            return probs.numpy()

        return "hf", predict, families

    ck = torch.load(path, map_location="cpu", weights_only=False)
    families = ck["families"]
    from features import FEATURE_NAMES
    n_saved = len(ck["features"])
    if n_saved != len(FEATURE_NAMES):
        raise SystemExit(
            f"[-] чекпоинт {path} обучен на {n_saved} признаках, "
            f"а features.py даёт {len(FEATURE_NAMES)} — модели несовместимы, "
            f"переобучи (--out с другим именем)")
    model = build(ck["arch"], len(ck["features"]), len(families), **(ck.get("kw") or {}))
    model.load_state_dict(ck["model"])
    model.eval()

    def predict(data):
        with torch.no_grad():
            logits = model(torch.from_numpy(byte_ids(data)).unsqueeze(0),
                           torch.from_numpy(hand_features(data)).unsqueeze(0),
                           torch.from_numpy(byte_hist(data)).unsqueeze(0))
        return torch.softmax(logits.float(), dim=1)[0].numpy()

    return ck["arch"], predict, families


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True)
    ap.add_argument("--dir", required=True)
    ap.add_argument("--min-size", type=int, default=24)
    ap.add_argument("--max-files", type=int, default=80)
    ap.add_argument("--top", type=int, default=3)
    ap.add_argument("--threshold", type=float, default=0.5)
    args = ap.parse_args()

    kind, predict, families = load(args.model)
    print(f"[+] модель: {kind}, классов: {len(families)}", flush=True)

    files = []
    for root, _dirs, names in os.walk(args.dir):
        for name in sorted(names):
            p = os.path.join(root, name)
            if os.path.getsize(p) >= args.min_size:
                files.append(p)
    files.sort()
    print(f"[+] файлов: {len(files)}", flush=True)

    tallies, unsure = {}, 0
    for p in files[:args.max_files]:
        data = open(p, "rb").read()
        probs = predict(data)
        idx = np.argsort(-probs)[:args.top]
        best = float(probs[idx[0]])
        rel = os.path.relpath(p, args.dir)
        tag = "" if best >= args.threshold else "  [не уверен]"
        unsure += best < args.threshold
        tallies[families[idx[0]]] = tallies.get(families[idx[0]], 0) + 1
        top = " | ".join(f"{families[i]} {probs[i]:.2f}" for i in idx)
        print(f"  {rel:52s} {len(data):>7d}B  {top}{tag}", flush=True)

    print("\n[=] сколько раз выбрано семейство:", flush=True)
    for fam, n in sorted(tallies.items(), key=lambda kv: -kv[1]):
        print(f"    {fam:12s} {n}", flush=True)
    print(f"[=] «не уверен»: {unsure}/{min(len(files), args.max_files)}", flush=True)


if __name__ == "__main__":
    main()
