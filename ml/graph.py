"""graph.py — детерминированный beam-поиск по цепочкам преобразований.

Зачем: роутер угадывает, "что это за артефакт", но цепочки вида
``xor -> base64 -> gzip -> flag`` нужно ИСКАТЬ. Этот модуль — слой поиска:
берём сырые байты, применяем дешёвые детерминированные операции, держим
самые перспективные промежуточные артефакты.

Оценка (score), см. ``_score``:
  * printable-ratio (больше печатных байт — лучше);
  * энтропия Шеннона в полосе 3.0..5.2 бит/байт (текст/код) — плюс,
    штраф за почти-нулевую и за почти-случайную;
  * флаг по regex ``[A-Za-z][A-Za-z0-9_]{1,15}\\{[^{}\\r\\n]{1,200}\\}`` —
    большой плюс, отдельный бонус за совпадение префикса (по умолчанию CTF);
  * бонус за "чистый" промежуточный артефакт — base64/hex/base32-подобный
    текст (именно так выглядят промежуточные шаги цепочек);
  * число "слов" (латиница, len>=3) и попадания в маленький словарь
    англ./флаг-слов;
  * бонус за известную магию контейнера (gzip/bz2/xz/zip/pdf/...);
  * штраф за глубину — каждый шаг стоит.

Защита от петель:
  * ``used_ops``: (sha256(данные), имя операции) — одну и ту же операцию к
    одинаковым байтам не запускаем дважды;
  * ``seen``: sha256(данные) — одинаковые байты, пришедшие разными путями,
    дальше не тащим (считаются в ``duplicates``);
  * no-progress pruning: ребёнок идёт в beam, только если score вырос
    больше чем на ``MIN_GAIN`` ИЛИ длина заметно упала (декод/сжатие).
    Иначе он оценивается (может стать best или отдать флаг), но не
    раскрывается; счётчик — ``pruned``. Исключение: на первом уровне
    нейтральные шаги (reverse/rot13, длина и score те же) ещё смотрим,
    иначе такие цепочки не пройти вообще.

Публичный API: ``search()``, ``to_text()``, ``find_flags()``.
CLI: ``python ml/graph.py --file PATH``.
"""
from __future__ import annotations

import argparse
import base64
import bz2
import hashlib
import lzma
import math
import re
import sys
import time
import zlib
from dataclasses import dataclass
from typing import Callable

# --- лимиты ---------------------------------------------------------------
MAX_OUTPUT = 8 * 1024 * 1024        # отказ, если операция даёт больше 8 МБ
BIG_INPUT = 2 * 1024 * 1024         # "бинарные" операции на входах > 2 МБ не запускаем
TEXT_INPUT = 8 * 1024 * 1024        # текстовым операциям хватает и 8 МБ
XOR_INPUT = 64 * 1024               # xor-брутфорс только на разумных входах
MIN_GAIN = 0.5                      # минимальный прирост score, чтобы раскрывать ребёнка
SHRINK_RATIO = 0.85                 # или длина упала хотя бы до 85%

FLAG_RE = re.compile(r"[A-Za-z][A-Za-z0-9_]{1,15}\{[^{}\r\n]{1,200}\}")
# тело флага: только "человеческие" символы; XOR-мусор с {\\]} и кавычками отсекаем
FLAG_BODY_RE = re.compile(r"[A-Za-z0-9_\-!?@#$%^&*()+=:;.,/ ]+")
WORD_RE = re.compile(r"[A-Za-z]{3,}")

MAGICS = (
    (b"\x1f\x8b", "gzip"),
    (b"BZh", "bz2"),
    (b"\xfd7zXZ\x00", "xz"),
    (b"PK\x03\x04", "zip"),
    (b"%PDF", "pdf"),
    (b"\x89PNG\r\n\x1a\n", "png"),
    (b"GIF8", "gif"),
    (b"SQLite format 3\x00", "sqlite"),
    (b"\x7fELF", "elf"),
    (b"MZ", "pe"),
)

# частые слова: грубый сигнал "это текст, а не мусор"
COMMON_WORDS = frozenset(
    "the and flag secret key password answer solve welcome hello world this that "
    "with from your you are not for was has have here find start use via or if "
    "is to of in it on by at be do".split()
)

_WS = b" \t\r\n\v\f"
_NONPRINT = bytes(range(0, 32)) + bytes(range(127, 256))
_B64_ALLOWED = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
_B32_ALLOWED = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567="
_HEX_ALLOWED = b"0123456789abcdefABCDEF"
_ALPHA = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
_ZW_CHARS = "\u200b\u200c\u200d\ufeff"
_ZW_TABLE = dict.fromkeys(map(ord, _ZW_CHARS))
_ROT13 = bytes.maketrans(
    _ALPHA, b"nopqrstuvwxyzabcdefghijklmNOPQRSTUVWXYZABCDEFGHIJKLM"
)
_CAESAR: dict[int, bytes] = {}
_MAX_SAMPLE = 65536


# --- мелкие утилиты -------------------------------------------------------
def _ratio_sample(data: bytes) -> bytes:
    """Для больших данных меряем статистику на выборке, а не на всём файле."""
    if len(data) <= _MAX_SAMPLE * 2:
        return data
    return data[:_MAX_SAMPLE] + data[-_MAX_SAMPLE:]


def _printable_ratio(data: bytes) -> float:
    """Доля печатных байт (ASCII 32..126 + \\t\\n\\r), 0..1."""
    if not data:
        return 0.0
    s = _ratio_sample(data)
    return len(s.translate(None, _NONPRINT)) / len(s)


def _entropy(data: bytes) -> float:
    """Энтропия Шеннона (бит/байт) по выборке до 8 КБ."""
    s = data[:8192]
    if not s:
        return 0.0
    counts = [0] * 256
    for b in s:
        counts[b] += 1
    n = len(s)
    h = 0.0
    for c in counts:
        if c:
            p = c / n
            h -= p * math.log2(p)
    return h


def _text_ratio(s: str) -> float:
    """Доля печатных символов в строке (по выборке)."""
    if not s:
        return 0.0
    sample = s if len(s) <= 20000 else s[:20000]
    ok = sum(1 for ch in sample if ch.isprintable() or ch in "\r\n\t")
    return ok / len(sample)


def to_text(data: bytes) -> str:
    """Байты -> строка для превью: utf-16 (BOM/много NUL), потом utf-8, иначе latin-1."""
    if not data:
        return ""
    if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
        try:
            return data.decode("utf-16")
        except UnicodeDecodeError:
            pass
    elif len(data) % 2 == 0 and data.count(0) * 8 > len(data):
        # NUL-ов много -> почти наверняка UTF-16 (utf-8 декодер их тоже "съест")
        for enc in ("utf-16-le", "utf-16-be"):
            try:
                s = data.decode(enc)
            except UnicodeDecodeError:
                continue
            if _text_ratio(s) >= 0.5:
                return s
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        pass
    return "".join(
        chr(b) if 32 <= b < 127 or b in (9, 10, 13) else "\u00b7" for b in data
    )


def _one_line(s: str, limit: int = 300) -> str:
    """Схлопнуть пробелы и обрезать — для превью в CLI/JSON."""
    return " ".join(s.split())[:limit]


def find_flags(data: bytes, prefix: str | None = None) -> list[str]:
    """Найти флаги. Тело обязано быть printable ASCII — иначе на рандоме ложняк.

    ``prefix`` (например "CTF") фильтрует результат по началу флага.
    Без префикса тело требуем длиннее (6+ символов и 3+ букв/цифр): так
    отсекается мусор вида ``m8z{q8}`` из неверных XOR-ключей.
    """
    if not data or b"{" not in data:
        return []
    if _printable_ratio(data) < 0.6:  # флаги живут в тексте, а не в бинаре
        return []
    text = data.decode("latin-1")
    out: list[str] = []
    low = prefix.lower() if prefix else ""
    min_body = 4 if low else 6
    for m in FLAG_RE.finditer(text):
        s = m.group(0)
        body = s[s.index("{") + 1 : -1]
        if len(body) < min_body or not FLAG_BODY_RE.fullmatch(body):
            continue
        if not low and sum(c.isalnum() for c in body) < 3:
            continue
        if low and not s.lower().startswith(low):
            continue
        out.append(s)
    return out


def _encoding_bonus(data: bytes) -> float:
    """Плюс за "чистый" промежуточный артефакт: base64/hex/base32-подобный текст.

    Именно так выглядят промежуточные шаги цепочек, поэтому это сильный сигнал
    не хуже printable-ratio.
    """
    core = data.translate(None, _WS)
    if len(core) < 8:
        return 0.0
    if not core.translate(None, _B64_ALLOWED):
        return 1.2
    if len(core) % 2 == 0 and not core.translate(None, _HEX_ALLOWED):
        return 1.1
    if not core.translate(None, _B32_ALLOWED):
        return 1.0
    return 0.0


def _score(data: bytes, depth: int, prefix: str | None = None) -> float:
    """Эвристическая оценка артефакта: текст/флаг/структура минус глубина."""
    if not data:
        return -10.0
    pr = _printable_ratio(data)
    h = _entropy(data)
    s = 2.0 * pr

    if 3.0 <= h <= 5.2:
        s += 0.8
    elif h > 6.5:
        s -= 0.6
    elif h < 2.0:
        s -= 0.5

    flags = find_flags(data, prefix or None)
    if flags:
        # бонус только за флаг с нужным префиксом: иначе любой мусор с фигурными
        # скобками (типичный побочный продукт неверного XOR-ключа) лезет в топ
        s += 12.0 + min(len(flags), 3)

    s += _encoding_bonus(data)

    sample = data[:4096].decode("latin-1")
    words = WORD_RE.findall(sample)
    if words:
        s += min(len(words), 20) * 0.03
        hits = sum(1 for w in words if w.lower() in COMMON_WORDS)
        s += min(hits, 10) * 0.25

    head = data[:64]
    for magic, _name in MAGICS:
        if head.startswith(magic):
            s += 0.9  # узнаваемый контейнер — стоит раскрыть
            break

    s -= 0.35 * depth
    return s


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# --- операции -------------------------------------------------------------
@dataclass(frozen=True)
class Op:
    """Операция реестра: name, fn(data, ctx) -> [(out_bytes, params), ...]."""

    name: str
    fn: Callable[[bytes, dict], list[tuple[bytes, dict]]]
    cost: int = 1
    max_input: int = TEXT_INPUT
    max_depth: int = 99


def op_b64(data: bytes, ctx: dict) -> list[tuple[bytes, dict]]:
    """base64 (с добивкой padding, url-safe при '-'/'_')."""
    core = data.translate(None, _WS)
    if len(core) < 8 or core.translate(None, _B64_ALLOWED):
        return []
    urlsafe = b"-" in core or b"_" in core
    pad = b"=" * ((-len(core)) % 4)
    try:
        out = base64.b64decode(
            core + pad, altchars=b"-_" if urlsafe else None
        )
    except Exception:
        return []
    if len(out) < 4 or out == data:
        return []
    return [(out, {"variant": "urlsafe" if urlsafe else "std"})]


def op_b32(data: bytes, ctx: dict) -> list[tuple[bytes, dict]]:
    """base32 (RFC 4648, регистр приводим)."""
    core = data.translate(None, _WS).upper()
    if len(core) < 8 or core.translate(None, _B32_ALLOWED):
        return []
    core = core.rstrip(b"=")
    pad = b"=" * ((-len(core)) % 8)
    try:
        out = base64.b32decode(core + pad)
    except Exception:
        return []
    return [(out, {"variant": "std"})] if len(out) >= 4 and out != data else []


def op_b85(data: bytes, ctx: dict) -> list[tuple[bytes, dict]]:
    """base85 (RFC 1924 / git-стиль)."""
    core = data.translate(None, _WS)
    if len(core) < 8:
        return []
    try:
        out = base64.b85decode(core)
    except Exception:
        return []
    return [(out, {"variant": "b85"})] if len(out) >= 4 and out != data else []


def op_hex(data: bytes, ctx: dict) -> list[tuple[bytes, dict]]:
    """hex, в том числе с префиксом 0x."""
    core = data.translate(None, _WS)
    if core[:2].lower() == b"0x":
        core = core[2:]
    if len(core) < 4 or len(core) % 2 or core.translate(None, _HEX_ALLOWED):
        return []
    try:
        out = bytes.fromhex(core.decode("ascii"))
    except ValueError:
        return []
    return [(out, {"step": 2})] if out and out != data else []


def op_rot13(data: bytes, ctx: dict) -> list[tuple[bytes, dict]]:
    """ROT13 по латинице."""
    if _printable_ratio(data) < 0.85:
        return []
    out = data.translate(_ROT13)
    return [(out, {"shift": 13})] if out != data else []


def _caesar_table(k: int) -> bytes:
    if k not in _CAESAR:
        lo = bytes(((c - 97 + k) % 26) + 97 for c in range(97, 123))
        up = bytes(((c - 65 + k) % 26) + 65 for c in range(65, 91))
        _CAESAR[k] = bytes.maketrans(_ALPHA, lo + up)
    return _CAESAR[k]


def op_caesar_all(data: bytes, ctx: dict) -> list[tuple[bytes, dict]]:
    """Все сдвиги 1..25, только печатные результаты (>=0.9) и только если вход текстовый."""
    if _printable_ratio(data) < 0.85:
        return []
    res: list[tuple[bytes, dict]] = []
    for k in range(1, 26):
        out = data.translate(_caesar_table(k))
        if out == data or _printable_ratio(out) < 0.9:
            continue
        res.append((out, {"shift": k}))
    return res


def op_reverse(data: bytes, ctx: dict) -> list[tuple[bytes, dict]]:
    """Реверс байтов."""
    return [(data[::-1], {"mode": "bytes"})]


def _xor(data: bytes, k: int) -> bytes:
    """XOR всего буфера одним байтом — через big-int, чтобы было быстро."""
    n = len(data)
    return (int.from_bytes(data, "big") ^ int.from_bytes(bytes([k]) * n, "big")).to_bytes(
        n, "big"
    )


def op_xor(data: bytes, ctx: dict) -> list[tuple[bytes, dict]]:
    """Однобайтовый XOR-брутфорс: печатное (>=0.85) или флаг. Дорогая операция."""
    if not 2 <= len(data) <= XOR_INPUT:
        return []
    res: list[tuple[bytes, dict]] = []
    for k in range(1, 256):
        out = _xor(data, k)
        if _printable_ratio(out) >= 0.85 or (b"{" in out and find_flags(out)):
            res.append((out, {"key": k}))
    return res


def op_gzip(data: bytes, ctx: dict) -> list[tuple[bytes, dict]]:
    """gzip-декомпрессия; отказ, если распухает больше MAX_OUTPUT."""
    if not data.startswith(b"\x1f\x8b"):
        return []
    try:
        d = zlib.decompressobj(16 + zlib.MAX_WBITS)
        out = d.decompress(data, MAX_OUTPUT + 1)
        if len(out) > MAX_OUTPUT or not d.eof:
            return []
    except zlib.error:
        return []
    return [(out, {"algo": "gzip"})] if out and out != data else []


def op_zlib(data: bytes, ctx: dict) -> list[tuple[bytes, dict]]:
    """zlib (DEFLATE с заголовком)."""
    if len(data) < 4:
        return []
    try:
        d = zlib.decompressobj()
        out = d.decompress(data, MAX_OUTPUT + 1)
        if len(out) > MAX_OUTPUT or not d.eof:
            return []
    except zlib.error:
        return []
    return [(out, {"algo": "zlib"})] if out and out != data else []


def op_bz2(data: bytes, ctx: dict) -> list[tuple[bytes, dict]]:
    """bzip2-декомпрессия."""
    if not data.startswith(b"BZh"):
        return []
    try:
        d = bz2.BZ2Decompressor()
        out = d.decompress(data, max_length=MAX_OUTPUT + 1)
        if len(out) > MAX_OUTPUT or not d.eof:
            return []
    except (OSError, EOFError, ValueError):
        return []
    return [(out, {"algo": "bz2"})] if out and out != data else []


def op_lzma(data: bytes, ctx: dict) -> list[tuple[bytes, dict]]:
    """xz/lzma-декомпрессия."""
    if len(data) < 8:
        return []
    if not (data.startswith(b"\xfd7zXZ\x00") or data[0] < 225):
        return []
    try:
        d = lzma.LZMADecompressor()
        out = d.decompress(data, max_length=MAX_OUTPUT + 1)
        if len(out) > MAX_OUTPUT or not d.eof:
            return []
    except (lzma.LZMAError, EOFError, ValueError):
        return []
    return [(out, {"algo": "lzma"})] if out and out != data else []


def _utf16_runs(data: bytes, little: bool, limit: int = 8) -> list[tuple[int, str]]:
    """Найти вкрапления UTF-16 (ASCII-символ + NUL) внутри бинарного контейнера.

    Так флаги лежат, например, в ID3-тегах MP3. Ищем серии вида
    (печатный, 0x00) для le или (0x00, печатный) для be, минимум 6 символов.
    """
    n = len(data)
    out: list[tuple[int, str]] = []
    i = 0
    while i + 1 < n and len(out) < limit:
        if little:
            ok = data[i + 1] == 0 and 32 <= data[i] < 127
        else:
            ok = data[i] == 0 and 32 <= data[i + 1] < 127
        if not ok:
            i += 1
            continue
        start = i
        while i + 1 < n:
            if little:
                ok = data[i + 1] == 0 and 32 <= data[i] < 127
            else:
                ok = data[i] == 0 and 32 <= data[i + 1] < 127
            if not ok:
                break
            i += 2
        if i - start >= 12:  # >= 6 символов
            enc = "utf-16-le" if little else "utf-16-be"
            try:
                s = data[start:i].decode(enc)
            except UnicodeDecodeError:
                pass
            else:
                out.append((start, s))
    return out


def op_utf16(data: bytes, ctx: dict) -> list[tuple[bytes, dict]]:
    """UTF-16 (le/be/bom) -> utf-8: файл целиком или run'ами внутри контейнера."""
    if len(data) < 4:
        return []
    res: list[tuple[bytes, dict]] = []

    # 1) файл целиком — только если это текст (BOM или заметная доля NUL)
    if len(data) % 2 == 0 and (
        data[:2] in (b"\xff\xfe", b"\xfe\xff") or data.count(0) * 20 >= len(data)
    ):
        variants: list[tuple[str, str]] = []
        if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
            variants.append(("utf-16", "bom"))
        else:
            variants = [("utf-16-le", "le"), ("utf-16-be", "be")]
        for enc, tag in variants:
            try:
                s = data.decode(enc)
            except UnicodeDecodeError:
                continue
            if len(s) < 2 or _text_ratio(s) < 0.85:
                continue
            out = s.encode("utf-8")
            if out and out != data:
                res.append((out, {"endian": tag}))
        if res:
            return res

    # 2) вкрапления внутри бинарного файла (ID3 и т.п.) — дешёвый скан по NUL
    if data.count(0) < 8:
        return []
    for tag, little in (("le", True), ("be", False)):
        for offset, s in _utf16_runs(data, little):
            if _text_ratio(s) < 0.85:
                continue
            out = s.strip().encode("utf-8")
            if len(out) >= 6 and out != data:
                res.append((out, {"endian": tag, "offset": offset}))
    return res


def op_strip_zw(data: bytes, ctx: dict) -> list[tuple[bytes, dict]]:
    """Убрать zero-width символы U+200B/200C/200D/FEFF."""
    try:
        s = data.decode("utf-8")
    except UnicodeDecodeError:
        return []
    if not any(ch in s for ch in _ZW_CHARS):
        return []
    out = s.translate(_ZW_TABLE).encode("utf-8")
    return [(out, {"removed": len(data) - len(out)})] if out and out != data else []


# реестр; порядок = по возрастанию стоимости (дешёвое раньше)
OPS: tuple[Op, ...] = tuple(
    sorted(
        (
            Op("b64_decode", op_b64, cost=1),
            Op("b32_decode", op_b32, cost=1),
            Op("b85_decode", op_b85, cost=1),
            Op("hex_decode", op_hex, cost=1),
            Op("rot13", op_rot13, cost=1),
            Op("reverse", op_reverse, cost=1),
            Op("strip_zero_width", op_strip_zw, cost=1),
            Op("caesar_all", op_caesar_all, cost=2),
            Op("utf16_decode", op_utf16, cost=2, max_input=BIG_INPUT),
            Op("gzip_decompress", op_gzip, cost=4, max_input=BIG_INPUT),
            Op("zlib_decompress", op_zlib, cost=4, max_input=BIG_INPUT),
            Op("bz2_decompress", op_bz2, cost=5, max_input=BIG_INPUT),
            Op("lzma_decompress", op_lzma, cost=6, max_input=BIG_INPUT),
            Op("xor_bruteforce", op_xor, cost=15, max_input=XOR_INPUT, max_depth=4),
        ),
        key=lambda o: o.cost,
    )
)


# --- поиск ---------------------------------------------------------------
@dataclass
class Node:
    """Узел поиска: байты, провенанс (цепочка (op, params)) и score."""

    data: bytes
    path: tuple[tuple[str, dict], ...]
    score: float
    depth: int
    expandable: bool = True


def _path_json(node: Node) -> list[dict]:
    """Провенанс в JSON-совместимом виде."""
    return [{"op": name, "params": dict(params)} for name, params in node.path]


def _scan(node: Node, found: dict[str, Node], prefix: str) -> None:
    """Запомнить флаги узла (первое/самое мелкое вхождение побеждает)."""
    for f in find_flags(node.data, prefix):
        found.setdefault(f, node)


def search(
    data: bytes,
    max_depth: int = 6,
    beam: int = 8,
    budget: int = 400,
    prefix: str = "CTF",
    verbose: bool = False,
) -> dict:
    """Beam-поиск цепочек преобразований с жёсткой защитой от петель.

    Возвращает::

        {
          "found": [{"flag": str, "path": [...], "depth": int}, ...],
          "best":  {"score": float, "path": [...], "preview": str},
          "stats": {"expanded": int, "pruned": int,
                    "duplicates": int, "seconds": float},
        }
    """
    t0 = time.time()
    data = bytes(data)
    per_op_cap = max(1, beam // 4)  # не даём одной операции забить весь beam
    stats = {"expanded": 0, "pruned": 0, "duplicates": 0, "seconds": 0.0}

    root = Node(data, (), _score(data, 0, prefix), 0)
    seen: dict[str, float] = {_digest(data): root.score}
    used_ops: set[tuple[str, str]] = set()
    found: dict[str, Node] = {}
    best = root
    _scan(root, found, prefix)

    frontier = [root]
    depth = 0

    while frontier and depth < max_depth and stats["expanded"] < budget:
        depth += 1
        cands: list[Node] = []
        for node in sorted(frontier, key=lambda n: n.score, reverse=True):
            if stats["expanded"] >= budget:
                break
            stats["expanded"] += 1
            h = _digest(node.data)
            for op in OPS:
                if depth > op.max_depth:          # тяжёлые операции — не глубоко
                    continue
                if len(node.data) > op.max_input:  # гигантские входы не трогаем
                    continue
                key = (h, op.name)
                if key in used_ops:
                    stats["duplicates"] += 1
                    continue
                used_ops.add(key)
                try:
                    results = op.fn(node.data, {"depth": depth, "prefix": prefix})
                except Exception:  # любая операция не имеет права уронить поиск
                    results = []

                fresh: list[Node] = []
                for out, params in results:
                    if not out:
                        continue
                    if len(out) > MAX_OUTPUT:
                        continue
                    if out == node.data:  # самопетля (reverse/rot13/…)
                        stats["duplicates"] += 1
                        continue
                    sig = _digest(out)
                    if sig in seen:
                        stats["duplicates"] += 1
                        continue
                    sc = _score(out, depth, prefix)
                    seen[sig] = sc

                    shorter = len(out) <= len(node.data) * SHRINK_RATIO
                    # "no-progress" правило: без прироста score и без заметного
                    # усыхания ребёнка дальше не раскрываем. Исключение — первый
                    # уровень: нейтральные шаги (reverse/rot13) ещё смотрим.
                    progress = sc > node.score + MIN_GAIN or shorter
                    keep = progress or depth <= 1
                    child = Node(
                        out, node.path + ((op.name, dict(params)),), sc, depth, keep
                    )
                    _scan(child, found, prefix)
                    if sc > best.score:
                        best = child
                    if not keep:
                        stats["pruned"] += 1
                    fresh.append(child)

                # per-op cap: самые перспективные дети этой операции
                if len(fresh) > per_op_cap:
                    fresh.sort(key=lambda n: n.score, reverse=True)
                    fresh = fresh[:per_op_cap]
                cands.extend(fresh)

                if verbose:
                    print(
                        f"d{depth} {op.name:<16} in={len(node.data):<7} "
                        f"out={len(results):<3} keep={len(fresh):<2} "
                        f"score={node.score:.2f}",
                        file=sys.stderr,
                    )

        cands.sort(key=lambda n: n.score, reverse=True)
        frontier = [n for n in cands if n.expandable][:beam]

    stats["seconds"] = round(time.time() - t0, 3)
    found_list = [
        {"flag": f, "path": _path_json(n), "depth": n.depth}
        for f, n in sorted(found.items(), key=lambda kv: (kv[1].depth, kv[0]))
    ]
    return {
        "found": found_list,
        "best": {
            "score": round(best.score, 3),
            "path": _path_json(best),
            "preview": _one_line(to_text(best.data), 240),
        },
        "stats": stats,
    }


def _fmt_path(path: list[dict]) -> str:
    if not path:
        return "(исходные байты)"
    parts = []
    for step in path:
        params = step["params"]
        arg = ",".join(f"{k}={v}" for k, v in params.items())
        parts.append(f"{step['op']}({arg})" if arg else step["op"])
    return " -> ".join(parts)


def main(argv: list[str] | None = None) -> int:
    """CLI: прогнать поиск по файлу и напечатать флаги + лучший путь."""
    ap = argparse.ArgumentParser(description="beam-поиск цепочек преобразований")
    ap.add_argument("--file", required=True, help="входной файл")
    ap.add_argument("--max-depth", type=int, default=6)
    ap.add_argument("--beam", type=int, default=8)
    ap.add_argument("--budget", type=int, default=400)
    ap.add_argument("--prefix", default="CTF", help="префикс флага ('' = любой)")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args(argv)

    try:
        with open(args.file, "rb") as f:
            data = f.read()
    except OSError as e:
        print(f"не могу прочитать {args.file}: {e}", file=sys.stderr)
        return 2

    res = search(
        data,
        max_depth=args.max_depth,
        beam=args.beam,
        budget=args.budget,
        prefix=args.prefix,
        verbose=args.verbose,
    )
    st = res["stats"]
    print(f"файл: {args.file} ({len(data)} байт)")
    print(
        f"поиск: beam={args.beam} depth={args.max_depth} budget={args.budget} "
        f"prefix={args.prefix or '(любой)'!r}"
    )
    if res["found"]:
        print(f"флаги ({len(res['found'])}):")
        for item in res["found"]:
            print(f"  {item['flag']}  (глубина {item['depth']})")
            print(f"    {_fmt_path(item['path'])}")
    else:
        print("флаги: не найдено")
    b = res["best"]
    print(f"лучший score={b['score']}")
    print(f"  {_fmt_path(b['path'])}")
    print(f"  превью: {b['preview']}")
    print(
        f"статистика: expanded={st['expanded']} pruned={st['pruned']} "
        f"duplicates={st['duplicates']} seconds={st['seconds']}"
    )
    return 0 if res["found"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
