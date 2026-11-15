"""np_router.py — тот же роутер, но на чистом numpy (без torch).

Кит запускается системным Python, где torch нет. Чтобы модель была доступна
солверу, а не жила только в экспериментах, веса выгружаются в .npz
(`export_numpy.py`), а forward считается вручную: три линейных слоя + GELU.
Это ~1 мс на файл и никаких зависимостей.

Один и тот же класс обслуживает разные модели: признаки берутся из модуля,
имя которого сохранено в npz (`features_module`). Так реверс-модель
(`rev_features`) и pwn-модель (`pwn_features`) работают без отдельного кода.

  from np_router import Router
  r = Router(r"F:\\AIproject\\ml-runs\\router_best.npz")          # форматы
  r = Router(r"F:\\AIproject\\ml-runs\\rev_v1.npz.router")         # реверс
  r.top(data, k=3)             # [('png', 0.64), ('gif', 0.12), ...]
  r.is_confident(data)         # False, если max prob < порога

Точность: считается честный GELU (через erf), расхождение с torch < 1e-6.
"""
from __future__ import annotations

import importlib
import math
import os
import sys

import numpy as np

try:                       # Windows-консоль cp1251 не знает "█"
    for _stream in (sys.stdout, sys.stderr):
        _stream.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def _erf(x: np.ndarray) -> np.ndarray:
    """erf через аппроксимацию Абрамовица–Стигана (точность ~1.5e-7)."""
    sign = np.sign(x)
    x = np.abs(x)
    a1, a2, a3 = 0.254829592, -0.284496736, 1.421413741
    a4, a5 = -1.453152027, 1.061405429
    p = 0.3275911
    t = 1.0 / (1.0 + p * x)
    y = 1.0 - (((((a5 * t + a4) * t) + a3) * t + a2) * t + a1) * t * np.exp(-x * x)
    return sign * y


def _gelu(x: np.ndarray) -> np.ndarray:
    return 0.5 * x * (1.0 + _erf(x / math.sqrt(2.0)))


class Router:
    def __init__(self, path: str, features_module: str | None = None):
        d = np.load(path, allow_pickle=False)
        self.w1, self.b1 = d["w1"], d["b1"]
        self.w2, self.b2 = d["w2"], d["b2"]
        self.w3, self.b3 = d["w3"], d["b3"]
        self.families = [str(x) for x in d["families"]]
        self.features = [str(x) for x in d["features"]]
        self.temperature = float(d["temperature"]) if "temperature" in d.files else 1.0
        if features_module is None and "features_module" in d.files:
            features_module = str(d["features_module"])
        mod = importlib.import_module(features_module or "features")
        self.hand_features = mod.hand_features
        self.byte_hist = mod.byte_hist
        if len(self.features) != len(self.hand_features(b"x")):
            raise RuntimeError(
                f"{path}: обучен на {len(self.features)} признаках, "
                f"{mod.__name__} даёт {len(self.hand_features(b'x'))} — переэкспортируй")

    def logits(self, data: bytes) -> np.ndarray:
        x = np.concatenate([self.hand_features(data),
                            self.byte_hist(data)]).astype(np.float32)
        h = _gelu(x @ self.w1.T + self.b1)
        h = _gelu(h @ self.w2.T + self.b2)
        return h @ self.w3.T + self.b3

    def probs(self, data: bytes) -> np.ndarray:
        z = self.logits(data) / self.temperature
        z = z - z.max()
        e = np.exp(z)
        return e / e.sum()

    def top(self, data: bytes, k: int = 3):
        p = self.probs(data)
        idx = np.argsort(-p)[:k]
        return [(self.families[i], round(float(p[i]), 4)) for i in idx]

    def is_confident(self, data: bytes, threshold: float = 0.5) -> bool:
        return float(self.probs(data).max()) >= threshold


def main():
    if len(sys.argv) < 3:
        print("usage: np_router.py <router.npz> <file> [k]")
        return 2
    r = Router(sys.argv[1])
    k = int(sys.argv[3]) if len(sys.argv) > 3 else 5
    with open(sys.argv[2], "rb") as fh:
        data = fh.read()
    print(f"[+] {sys.argv[2]}: {len(data)} байт")
    for fam, p in r.top(data, k):
        print(f"    {fam:12s} {p:5.3f}  {'█' * int(p * 25)}")


if __name__ == "__main__":
    raise SystemExit(main() or 0)
