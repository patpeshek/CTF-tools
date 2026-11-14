"""export_numpy.py — выгрузить MLP-роутер в обычный .npz.

Зачем: кит работает на системном Python, где torch нет и ставить его ради
роутера — 2.5 ГБ. А MLP — это три линейных слоя и GELU, их можно считать
чистым numpy за микросекунды. Экспорт делает модель переносимой: тот же файл
читает и обучение (torch), и солвер (numpy).

  python ml/export_numpy.py --model F:\\AIproject\\ml-runs\\mlp_v10.pt ^
      --out F:\\AIproject\\ml-runs\\router_v10.npz
"""
from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import numpy as np
import torch

from model import build


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--temperature", type=float, default=1.0,
                    help="из calibrate.py: делим логиты на T")
    args = ap.parse_args()

    ck = torch.load(args.model, map_location="cpu", weights_only=False)
    if ck["arch"] != "mlp":
        raise SystemExit("[-] экспорт поддерживает только arch=mlp")
    model = build(ck["arch"], len(ck["features"]), len(ck["families"]),
                  **(ck.get("kw") or {}))
    model.load_state_dict(ck["model"])
    model.eval()

    arrays = {name: p.detach().numpy() for name, p in model.net.named_parameters()}
    need = ["0.weight", "0.bias", "3.weight", "3.bias", "6.weight", "6.bias"]
    missing = [k for k in need if k not in arrays]
    if missing:
        raise SystemExit(f"[-] нет слоёв {missing}; есть {sorted(arrays)}")

    np.savez(args.out,
             w1=arrays["0.weight"], b1=arrays["0.bias"],
             w2=arrays["3.weight"], b2=arrays["3.bias"],
             w3=arrays["6.weight"], b3=arrays["6.bias"],
             families=np.array(ck["families"]),
             features=np.array(ck["features"]),
             temperature=np.array(args.temperature, dtype=np.float32),
             arch=np.array("mlp"))
    size = os.path.getsize(args.out)
    print(f"[+] сохранено: {args.out} ({size / 1024:.0f} КБ), "
          f"классов {len(ck['families'])}, признаков {len(ck['features'])}")


if __name__ == "__main__":
    main()
