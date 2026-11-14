"""np_policy.py — политика «какой инструмент сработает» на чистом numpy.

Роутер (`np_router`) отвечает «что за файл». Политика отвечает «что делать»:
для текущего состояния задачи и конкретного инструмента даёт вероятность,
что этот шаг даст флаг. Обучена на трассах солвера (`train_policy.py`).

  from np_policy import Policy
  pol = Policy(r"F:\\AIproject\\ml-runs\\policy_big.npz")
  pol.rank("chall.bin", ["lsb", "png_chunks", "ocr", "chain"])
  # [('lsb', 0.71), ('png_chunks', 0.12), ...]
"""
from __future__ import annotations

import math
import os
import sys

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from features import byte_hist, hand_features


def _erf(x: np.ndarray) -> np.ndarray:
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


def _sigmoid(x: float) -> float:
    return 1.0 / (1.0 + math.exp(-max(-30.0, min(30.0, x))))


class Policy:
    def __init__(self, path: str):
        d = np.load(path, allow_pickle=False)
        self.w1, self.b1 = d["w1"], d["b1"]
        self.w2, self.b2 = d["w2"], d["b2"]
        self.w3, self.b3 = d["w3"], d["b3"]
        self.tools = [str(t) for t in d["tools"]]
        self.n_in = int(d["n_in"]) if "n_in" in d.files else None
        self.index = {name: i for i, name in enumerate(self.tools)}

    def _state(self, data: bytes) -> np.ndarray:
        return np.concatenate([hand_features(data), byte_hist(data)]).astype(np.float32)

    def score(self, state: np.ndarray, tool: str, pos: float = 0.0,
              ok: float = 1.0) -> float:
        width = (self.n_in - len(state) - 1) if self.n_in else len(self.tools)
        onehot = np.zeros(max(width, len(self.tools)), dtype=np.float32)
        idx = self.index.get(tool)
        if idx is None:
            # незнакомый инструмент: модель про него ничего не знает
            return 0.0
        onehot[idx] = 1.0
        x = np.concatenate([state, onehot, np.array([pos], dtype=np.float32)])
        h = _gelu(x @ self.w1.T + self.b1)
        h = _gelu(h @ self.w2.T + self.b2)
        out = np.ravel(h @ self.w3.T + self.b3)
        return _sigmoid(float(out[0]))

    def rank(self, data: bytes, tools, pos: float = 0.0):
        state = self._state(data)
        scored = [(t, self.score(state, t.split()[0], pos)) for t in tools]
        return sorted(scored, key=lambda kv: -kv[1])


def main():
    if len(sys.argv) < 3:
        print("usage: np_policy.py <policy.npz> <file> [tool,tool,...]")
        return 2
    pol = Policy(sys.argv[1])
    with open(sys.argv[2], "rb") as fh:
        data = fh.read()
    tools = (sys.argv[3].split(",") if len(sys.argv) > 3
             else ["lsb", "png_chunks", "ocr", "chain", "facts", "hunt", "rsa"])
    for name, p in pol.rank(data, tools):
        print(f"    {name:14s} {p:5.3f}  {'█' * int(p * 30)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
