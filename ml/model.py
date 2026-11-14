"""model.py — две маленькие модели для роутера.

FeatureMLP   — быстрый baseline на признаках и гистограмме байт.
ByteTransformer — char-level трансформер по первым 256 байтам + признаки.
Обе выдают ЛОГИТЫ по семействам (вероятности = softmax), т.е. это
decision model, а не генератор.
"""
from __future__ import annotations

import torch
from torch import nn


class FeatureMLP(nn.Module):
    def __init__(self, n_hand: int, n_hist: int, n_classes: int, hidden: int = 256,
                 depth: int = 2, dropout: float = 0.15):
        super().__init__()
        layers = [nn.Linear(n_hand + n_hist, hidden), nn.GELU(),
                  nn.Dropout(dropout)]
        width = hidden
        for _ in range(max(0, depth - 2)):
            layers += [nn.Linear(width, width), nn.GELU(), nn.Dropout(dropout)]
        layers += [nn.Linear(width, max(width // 2, 32)), nn.GELU(),
                   nn.Dropout(dropout), nn.Linear(max(width // 2, 32), n_classes)]
        self.net = nn.Sequential(*layers)

    def forward(self, x_bytes, x_hand, x_hist):
        return self.net(torch.cat([x_hand, x_hist], dim=1))


class ByteTransformer(nn.Module):
    def __init__(self, n_hand: int, n_classes: int, max_len: int = 256,
                 dim: int = 128, layers: int = 4, heads: int = 4,
                 ff: int = 256, dropout: float = 0.1):
        super().__init__()
        self.max_len = max_len
        self.embed = nn.Embedding(257, dim, padding_idx=0)
        self.cls = nn.Parameter(torch.zeros(1, 1, dim))
        self.pos = nn.Parameter(torch.zeros(1, max_len + 1, dim))
        nn.init.normal_(self.cls, std=0.02)
        nn.init.normal_(self.pos, std=0.02)
        layer = nn.TransformerEncoderLayer(
            d_model=dim, nhead=heads, dim_feedforward=ff, dropout=dropout,
            activation="gelu", batch_first=True, norm_first=True)
        self.encoder = nn.TransformerEncoder(layer, num_layers=layers)
        self.hand = nn.Linear(n_hand, dim)
        self.norm = nn.LayerNorm(dim)
        self.head = nn.Linear(dim, n_classes)

    def forward(self, x_bytes, x_hand, x_hist=None):
        x = self.embed(x_bytes.long())
        x = torch.cat([self.cls.expand(x.size(0), -1, -1), x], dim=1)
        x = x + self.pos[:, :x.size(1)]
        x = x + self.hand(x_hand).unsqueeze(1)
        x = self.encoder(x)
        return self.head(self.norm(x[:, 0]))


def build(arch: str, n_hand: int, n_classes: int, **kw):
    if arch == "mlp":
        return FeatureMLP(n_hand, 256, n_classes,
                          hidden=kw.get("hidden", 256),
                          depth=kw.get("depth", 2))
    if arch == "transformer":
        return ByteTransformer(n_hand, n_classes, **kw)
    raise ValueError(arch)
