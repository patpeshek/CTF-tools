"""features.py — признаки артефакта для роутера.

Ничего не решает: превращает байты в вектор, по которому модель/дерево
выбирает семейство и следующий инструмент. Часть признаков дублирует facts.py,
но здесь они в одном фиксированном порядке (важно для обучения).
"""
from __future__ import annotations

import base64
import math
import re
import zlib

import numpy as np

MAGICS = [
    (b"\x89PNG\r\n\x1a\n", "png"),
    (b"PK\x03\x04", "zip"),
    (b"\x1f\x8b", "gzip"),
    (b"\xfd7zXZ\x00", "xz"),
    (b"BZh", "bz2"),
    (b"%PDF", "pdf"),
    (b"\x7fELF", "elf"),
    (b"MZ", "pe"),
    (b"SQLite format 3\x00", "sqlite"),
    (b"\xd4\xc3\xb2\xa1", "pcap"),
    (b"\xa1\xb2\xc3\xd4", "pcap"),
    (b"{\\rtf", "rtf"),
    (b"\xff\xd8\xff", "jpeg"),
    (b"GIF8", "gif"),
]

FLAG_RE = re.compile(rb"[A-Za-z][A-Za-z0-9_]{1,15}\{[^{}\r\n]{1,200}\}")
NUM_RE = re.compile(rb"\d{10,}")
B64_RE = re.compile(rb"^[A-Za-z0-9+/=\s]+$")
HEX_RE = re.compile(rb"^[0-9a-fA-F\s]+$")


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
    p = counts[counts > 0] / len(data)
    return float(-(p * np.log2(p)).sum())


def ioc(data: bytes) -> float:
    """Индекс совпадений: ~0.065 у текста, ~0.038 у случайных байт."""
    n = len(data)
    if n < 2:
        return 0.0
    counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
    return float((counts * (counts - 1)).sum() / (n * (n - 1)))


def _printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    arr = np.frombuffer(data, dtype=np.uint8)
    ok = ((arr >= 32) & (arr < 127)) | (arr == 9) | (arr == 10) | (arr == 13)
    return float(ok.mean())


def _b64_score(data: bytes) -> float:
    s = data.strip()
    if not s or len(s) < 8 or not B64_RE.match(s):
        return 0.0
    try:
        dec = base64.b64decode(s + b"=" * ((-len(s)) % 4), validate=False)
    except Exception:
        return 0.0
    return _printable_ratio(dec)


def _hex_score(data: bytes) -> float:
    s = data.strip()
    if not s or len(s) < 8 or len(s) % 2 or not HEX_RE.match(s):
        return 0.0
    try:
        return _printable_ratio(bytes.fromhex(s.decode()))
    except Exception:
        return 0.0


def hand_features(data: bytes) -> np.ndarray:
    n = max(1, len(data))
    arr = np.frombuffer(data, dtype=np.uint8) if data else np.zeros(0, np.uint8)
    printable = _printable_ratio(data)
    alpha = float(((arr >= 65) & (arr <= 90) | (arr >= 97) & (arr <= 122)).mean()) if len(arr) else 0.0
    digit = float(((arr >= 48) & (arr <= 57)).mean()) if len(arr) else 0.0
    space = float((arr == 32).mean()) if len(arr) else 0.0
    punct = float((((arr >= 33) & (arr <= 47)) | ((arr >= 58) & (arr <= 64)) |
                   ((arr >= 91) & (arr <= 96)) | ((arr >= 123) & (arr <= 126))).mean()) if len(arr) else 0.0
    uniq = float(len(set(data)) / n) if data else 0.0
    lines = data.count(b"\n") + 1 if data else 0
    max_line = max((len(x) for x in data.split(b"\n")), default=0) if data else 0
    trail = sum(1 for x in data.split(b"\n")
                if x.rstrip(b"\r").endswith((b" ", b"\t"))) if data else 0
    nums = NUM_RE.findall(data[:4096])
    max_digits = max((len(x) for x in nums), default=0)
    flags = len(FLAG_RE.findall(data[:4096]))
    try:
        data.decode("utf-8")
        utf8 = 1.0
    except Exception:
        utf8 = 0.0
    utf16 = 1.0 if (len(data) >= 8 and data[1:2] == b"\x00"
                    and sum(data[i] == 0 for i in range(0, min(len(data), 64), 2)) >= 16) else 0.0
    zratio = 0.0
    if len(data) >= 32:
        try:
            zratio = len(zlib.compress(data[:65536], 6)) / max(1, len(data[:65536]))
        except Exception:
            zratio = 1.0
    magic = [0.0] * len(MAGICS)
    for i, (sig, _name) in enumerate(MAGICS):
        if data.startswith(sig):
            magic[i] = 1.0
            break

    vec = [
        math.log1p(len(data)),
        entropy(data),
        printable, alpha, digit, space, punct, uniq,
        _b64_score(data), _hex_score(data),
        len(data) % 4 / 4.0, len(data) % 8 / 8.0, len(data) % 16 / 16.0,
        ioc(data), zratio,
        math.log1p(lines), math.log1p(max_line), math.log1p(trail),
        math.log1p(len(nums)), math.log1p(max_digits), min(flags, 3) / 3.0,
        utf8, utf16,
    ] + magic
    return np.asarray(vec, dtype=np.float32)


FEATURE_NAMES = [
    "size_log", "entropy", "printable", "alpha", "digit", "space", "punct",
    "uniq", "b64_score", "hex_score", "len_mod4", "len_mod8", "len_mod16",
    "ioc", "zlib_ratio", "lines_log", "maxline_log", "trail_ws_log",
    "nums_log", "maxdigits_log", "flag_count", "utf8", "utf16",
] + [f"magic_{name}" for _sig, name in MAGICS]


def byte_hist(data: bytes) -> np.ndarray:
    counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256).astype(np.float32)
    if counts.sum():
        counts /= counts.sum()
    return np.log1p(counts * 1000.0)


def byte_ids(data: bytes, max_len: int = 256) -> np.ndarray:
    """id = byte + 1, 0 = padding (чтобы отличать нулевой байт)."""
    out = np.zeros(max_len, dtype=np.uint8)
    chunk = data[:max_len]
    out[:len(chunk)] = np.frombuffer(chunk, dtype=np.uint8) + 1
    return out
