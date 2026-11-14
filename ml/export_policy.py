"""export_policy.py — выгрузить политику в numpy (кит живёт без torch).

Политика — это тот же MLP (вход: признаки файла + one-hot инструмента +
позиция шага), поэтому экспорт такой же, как у роутера: веса в .npz, forward
руками.

  python ml/export_policy.py --model F:\\AIproject\\ml-runs\\policy_big.pt ^
      --out F:\\AIproject\\ml-runs\\policy_big.npz
"""
from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import numpy as np
import torch


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    ck = torch.load(args.model, map_location="cpu", weights_only=False)
    sd = ck["model"]
    need = ["net.0.weight", "net.0.bias", "net.3.weight", "net.3.bias",
            "net.5.weight", "net.5.bias"]
    missing = [k for k in need if k not in sd]
    if missing:
        raise SystemExit(f"[-] нет слоёв {missing}")
    np.savez(args.out,
             w1=sd["net.0.weight"].numpy(), b1=sd["net.0.bias"].numpy(),
             w2=sd["net.3.weight"].numpy(), b2=sd["net.3.bias"].numpy(),
             w3=sd["net.5.weight"].numpy(), b3=sd["net.5.bias"].numpy(),
             tools=np.array(ck["tools"]),
             n_in=np.array(ck["n_in"]))
    print(f"[+] сохранено: {args.out} ({os.path.getsize(args.out) / 1024:.0f} КБ), "
          f"инструментов {len(ck['tools'])}")


if __name__ == "__main__":
    main()
