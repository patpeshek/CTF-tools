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
    (b"\x4d\x3c\xb2\xa1", "pcap"),
    (b"\xa1\xb2\x3c\x4d", "pcap"),
    (b"{\\rtf", "rtf"),
    (b"\xff\xd8\xff", "jpeg"),
    (b"GIF8", "gif"),
    (b"ID3", "mp3"),
    (b"\xff\xfb", "mp3raw"),
    (b"RIFF", "wav"),
    (b"\x0a\x0d\x0d\x0a", "pcapng"),
    (b"FORM", "aiff"),
    (b"caff", "caf"),
    (b"fLaC", "flac"),
    (b"OggS", "ogg"),
    (b"II*\x00", "tiff"),
    (b"MM\x00*", "tiff"),
    (b"7z\xbc\xaf\x27\x1c", "7z"),
    (b"Rar!\x1a\x07", "rar"),
    (b"\x1aE\xdf\xa3", "mkv"),
    (b"\x00asm", "wasm"),
    (b"8BPS", "psd"),
    (b"\x00\x00\x01\x00", "ico"),
    (b"DIRC", "git_index"),
    (b"PACK", "git_pack"),
]

FLAG_RE = re.compile(rb"[A-Za-z][A-Za-z0-9_]{1,15}\{[^{}\r\n]{1,200}\}")
NUM_RE = re.compile(rb"\d{10,}")
B64_RE = re.compile(rb"^[A-Za-z0-9+/=\s]+$")
HEX_RE = re.compile(rb"^[0-9a-fA-F\s]+$")

# «прогоны» — куски однородных данных внутри бинарника. Именно так находятся
# base64, вшитый в картинку, hex в PDF и UTF-16-теги внутри mp3.
B64_RUN_RE = re.compile(rb"[A-Za-z0-9+/]{40,}")
HEX_RUN_RE = re.compile(rb"(?:[0-9a-fA-F]{2}){20,}")
PRINT_RUN_RE = re.compile(rb"[\x20-\x7e\t]{40,}")
UTF16_LE_RUN_RE = re.compile(rb"(?:[\x20-\x7e\t\r\n][\x00\x04]){8,}")
UTF16_BE_RUN_RE = re.compile(rb"(?:[\x00\x04][\x20-\x7e\t\r\n]){8,}")
ZW_SEQS = (b"\xe2\x80\x8b", b"\xe2\x80\x8c", b"\xe2\x80\x8d", b"\xef\xbb\xbf")


def _max_run(rx, sample: bytes) -> int:
    return max((len(m.group(0)) for m in rx.finditer(sample)), default=0)


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
    # дорогие операции (regex, split, set) считаем по первым 64 КБ: на файлах
    # в мегабайты полный проход даёт те же признаки, но в 20 раз медленнее
    chunk = data[:65536]
    printable = _printable_ratio(data)
    alpha = float(((arr >= 65) & (arr <= 90) | (arr >= 97) & (arr <= 122)).mean()) if len(arr) else 0.0
    digit = float(((arr >= 48) & (arr <= 57)).mean()) if len(arr) else 0.0
    space = float((arr == 32).mean()) if len(arr) else 0.0
    punct = float((((arr >= 33) & (arr <= 47)) | ((arr >= 58) & (arr <= 64)) |
                   ((arr >= 91) & (arr <= 96)) | ((arr >= 123) & (arr <= 126))).mean()) if len(arr) else 0.0
    uniq = float(len(set(chunk)) / max(1, len(chunk))) if data else 0.0
    lines = data.count(b"\n") + 1 if data else 0
    body = chunk.split(b"\n")
    max_line = max((len(x) for x in body), default=0)
    trail = sum(1 for x in body
                if x.rstrip(b"\r").endswith((b" ", b"\t"))) if data else 0
    nums = NUM_RE.findall(data[:4096])
    max_digits = max((len(x) for x in nums), default=0)
    flags = len(FLAG_RE.findall(data[:4096]))
    try:
        data.decode("utf-8")
        utf8 = 1.0
    except Exception:
        utf8 = 0.0
    utf16 = 0.0
    if len(data) >= 8:
        # у UTF-16LE старший байт идёт вторым, у BE — первым; он нулевой для
        # латиницы и маленький (< 0x05) для кириллицы. Раньше проверка брала
        # чётные индексы при условии data[1:2] == 0 — признак был всегда нулём.
        head = min(len(data) - (len(data) % 2), 128)
        pairs = head // 2
        small_odd = sum(data[i] < 0x05 for i in range(1, head, 2))
        small_even = sum(data[i] < 0x05 for i in range(0, head, 2))
        if pairs >= 4 and max(small_odd, small_even) >= pairs * 0.9:
            utf16 = 1.0
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
    mbr = 1.0 if len(data) >= 512 and data[510:512] == b"\x55\xaa" else 0.0
    zero_frac = float((arr == 0).mean()) if len(arr) else 0.0

    # структурные «прогоны» и вложенные файлы — считаем по первым 64 КБ
    sample = data[:65536]
    rs = max(1, len(sample))
    b64_run = _max_run(B64_RUN_RE, sample) / rs
    hex_run = _max_run(HEX_RUN_RE, sample) / rs
    print_run = _max_run(PRINT_RUN_RE, sample) / rs
    utf16_run = max(_max_run(UTF16_LE_RUN_RE, sample),
                    _max_run(UTF16_BE_RUN_RE, sample)) / rs
    zw = sum(sample.count(s) for s in ZW_SEQS)
    zw_frac = min(1.0, zw / rs)
    # магия не в начале = файл внутри файла (png в zip, zip в pdf)
    embedded = min(sum(1 for sig, _nm in MAGICS if sample.find(sig, 1) > 0), 6) / 6.0
    head_text = 1.0 if data[:20] and all(32 <= b < 127 for b in data[:20]) else 0.0

    # «код или конфиг» — самая частая путаница на реальных файлах: короткий
    # solver-скрипт и dotenv-конфиг выглядят одинаково (много «=», мало слов).
    # Считаем ключевые слова языка против строк вида KEY=value / [section].
    low = chunk.lower()
    n_lines = sum(1 for ln in body if ln.strip())
    code_kw = sum(low.count(k) for k in (b"def ", b"class ", b"import ", b"return ",
                                         b"for ", b"while ", b"print(", b"self.",
                                         b"#include", b"int main", b"func "))
    code_score = min(1.0, code_kw / max(1, n_lines) / 2.0)
    assign = sum(1 for ln in body
                 if re.match(rb"^\s*[A-Za-z_][\w.\-]*\s*[:=]\s*\S", ln))
    cfg_score = min(1.0, assign / max(1, n_lines))
    bracket = float(((arr == 123) | (arr == 125) | (arr == 40) | (arr == 41)).mean()) if len(arr) else 0.0
    # на бинарнике эти признаки — чистый шум (скобки встречаются случайно),
    # из-за этого ELF уезжал в sqlite/xor. Обнуляем, если это не текст.
    if printable < 0.8:
        code_score = cfg_score = bracket = 0.0

    # свободный объект git: zlib, а внутри «blob N\0…». Магия та же, что у
    # zlib-текста, поэтому проверяем распакованную голову.
    git_loose = 0.0
    if data[:1] == b"\x78" and len(data) > 16:
        try:
            head_dec = zlib.decompressobj().decompress(chunk, 64)
            if head_dec[:5] in (b"blob ", b"tree ", b"commi", b"tag "):
                git_loose = 1.0
        except Exception:
            pass

    vec = [
        math.log1p(len(data)),
        entropy(chunk),
        printable, alpha, digit, space, punct, uniq,
        _b64_score(chunk), _hex_score(chunk),
        len(data) % 4 / 4.0, len(data) % 8 / 8.0, len(data) % 16 / 16.0,
        ioc(chunk), zratio,
        math.log1p(lines), math.log1p(max_line), math.log1p(trail),
        math.log1p(len(nums)), math.log1p(max_digits), min(flags, 3) / 3.0,
        utf8, utf16,
        b64_run, hex_run, print_run, utf16_run, zw_frac, embedded, head_text,
        zero_frac, code_score, cfg_score, bracket, git_loose,
    ] + magic + [mbr]
    return np.asarray(vec, dtype=np.float32)


FEATURE_NAMES = [
    "size_log", "entropy", "printable", "alpha", "digit", "space", "punct",
    "uniq", "b64_score", "hex_score", "len_mod4", "len_mod8", "len_mod16",
    "ioc", "zlib_ratio", "lines_log", "maxline_log", "trail_ws_log",
    "nums_log", "maxdigits_log", "flag_count", "utf8", "utf16",
    "b64_run", "hex_run", "print_run", "utf16_run", "zw_frac", "embedded",
    "head_text", "zero_frac", "code_score", "cfg_score", "bracket",
    "git_loose",
] + [f"magic_{name}" for _sig, name in MAGICS] + ["mbr"]


def byte_hist(data: bytes) -> np.ndarray:
    counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256).astype(np.float32)
    if counts.sum():
        counts /= counts.sum()
    return np.log1p(counts * 1000.0)


def byte_ids(data: bytes, max_len: int = 256) -> np.ndarray:
    """id = байт + 1 (1..256), 0 = padding.

    Тип int16, а не uint8: 0xFF + 1 = 256 не влезает в uint8 и превращался
    в 0, то есть в паддинг. Для mp3/jpeg/elf, где первые байты часто 0xFF,
    это стирало начало файла — самый информативный кусок.
    """
    out = np.zeros(max_len, dtype=np.int16)
    chunk = data[:max_len]
    out[:len(chunk)] = np.frombuffer(chunk, dtype=np.uint8).astype(np.int16) + 1
    return out
