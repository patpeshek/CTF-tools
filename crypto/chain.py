#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
chain.py — многослойные цепочки кодировок: base64 → hex → ROT13 → XOR → флаг.

  python crypto/chain.py "<строка>"
  python crypto/chain.py blob.txt                 # файл позицией
  python crypto/chain.py --file blob.bin --depth 8 --beam 40 --time 30

Поиск лучом (beam search) по декодерам. Строгие (проверяют алфавит/сигнатуру):
base64/base64url/base32/base85/ascii85, hex, двоичный, десятичный, восьмеричный,
url, zlib/gzip/bz2/xz. Слабые (применимы всегда): ROT13, лучшие ROT-N, ROT47,
Atbash, реверс, NOT, однобайтовый XOR (лучшие ключи по читаемости) и XOR по
известному префиксу флага; для текстовых узлов — ещё все декодеры enc.py.

Каждый новый узел сразу проверяется на флаг, в том числе «на шаг вперёд» через
XOR — так последний слой не теряется, даже если промежуточный узел бинарный.
Защита от взрыва: глубина, ширина луча (отдельная квота для строгих декодеров),
дедуп по хешу, бюджет узлов и времени. Оценка: доля печатных символов +
похожесть на текст/флаг + бонус за «ещё декодируемую» форму (hex/base64/...).
Стоп на первом настоящем флаге (common.find_flags, без заглушек).
"""
from __future__ import annotations

# Windows: консоль/pipe не должны падать на Unicode (—, →, «», █).
try:
    import sys as _sys
    for _stream in (_sys.stdout, _sys.stderr):
        _stream.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

import argparse
import base64
import binascii
import bz2
import gzip
import hashlib
import lzma
import os
import re
import sys
import time
import urllib.parse
import zlib

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)
import common  # noqa: E402

try:  # все однослойные декодеры enc.py — не дублировать
    import enc as _enc  # noqa: E402
except Exception:  # pragma: no cover - enc.py всегда рядом, но не падать
    _enc = None

STUB_WORDS = ("missing", "placeholder", "dummy", "fake")
MAX_ROOT = 256 * 1024
MAX_NODE = 1024 * 1024
TEXT_OPS_LIMIT = 20000      # enc.try_all на больших текстах медленный: корень
TEXT_OPS_NODE = 1024        # ... и промежуточные узлы
DEEP_MIN_INNER = 5          # флаг глубже одного слоя: минимум символов внутри {}
DEEP_MIN_PLAUS = 1.5        # ... и минимальная flag_plausibility()
XOR_SAMPLE = 2048

_UP = bytes(range(65, 91))
_LO = bytes(range(97, 123))
PRINTABLE = bytes(range(32, 127)) + b"\t\r\n"
LETTERS = _UP + _LO
WORDISH = LETTERS + b"0123456789_ {}.,!?'-"
FREQ = b"etaoinshrdluETAOINSHRDLU "
XOR_TABLES = [bytes(b ^ k for b in range(256)) for k in range(256)]
ROT_TABLES = [bytes.maketrans(_UP + _LO, _UP[n:] + _UP[:n] + _LO[n:] + _LO[:n])
              for n in range(26)]
ATBASH = bytes.maketrans(_UP + _LO, _UP[::-1] + _LO[::-1])
ROT47 = bytes.maketrans(bytes(range(33, 127)),
                        bytes(33 + ((c - 33 + 47) % 94) for c in range(33, 127)))

_FLAGSHAPE = re.compile(rb"[A-Za-z][A-Za-z0-9_]{1,24}\{[\x20-\x7a\x7c\x7e]{3,}\}")
_HEX_RE = re.compile(rb"[0-9a-fA-F]+")
_B64_RE = re.compile(rb"[A-Za-z0-9+/]+={0,2}")
_B64URL_RE = re.compile(rb"[A-Za-z0-9_\-]+={0,2}")
_B32_RE = re.compile(rb"[A-Z2-7]+=*")
_B85_RE = re.compile(rb"[0-9A-Za-z!#$%&()*+\-;<=>?@^_`{|}~]+")
_BIN_RE = re.compile(rb"[01\s]+")
_DEC_RE = re.compile(rb"\d{1,3}(?:[\s,;]+\d{1,3})+")
_OCT_RE = re.compile(rb"(?:\\?[0-7]{3}[\s,]*){2,}")
_MORSE_RE = re.compile(rb"[.\-/|_\s]+")


def count_in(b: bytes, alphabet: bytes) -> int:
    """Сколько байтов b входят в alphabet (через translate — быстро)."""
    return len(b) - len(b.translate(None, alphabet))


def printable_ratio(b: bytes) -> float:
    return count_in(b, PRINTABLE) / len(b) if b else 0.0


def real_flags(data: bytes):
    found = common.find_flags(data)
    return [f for f in found if not any(w in f.lower() for w in STUB_WORDS)]


def quality(b: bytes) -> float:
    """Читаемость: печатность + похожесть на текст/флаг + «ещё декодируется»."""
    n = len(b)
    if not n:
        return -10.0
    p = count_in(b, PRINTABLE) / n
    s = 2.0 * p + 0.5 * count_in(b, WORDISH) / n + 1.0 * count_in(b, FREQ) / n
    if n < 4:
        s -= 1.0
    if p < 0.97:
        return s
    if _FLAGSHAPE.search(b):
        s += 2.0
    low = b.lower()
    if any((pre.lower() + "{").encode() in low for pre in common.prefixes()):
        s += 1.0
    # «ещё декодируется»: чем уже алфавит, тем реже он получается случайно
    shape = narrow_shape(b)
    s += {"bin": 1.2, "hex": 1.0, "dec": 0.8, "morse": 1.0, "b32": 0.5,
          "b64": 0.4}.get(shape, 0.0)
    return s


def narrow_shape(b: bytes) -> str:
    """Форма текста, которую понимает строгий декодер: bin/hex/dec/morse/b32/b64."""
    t = re.sub(rb"\s+", b"", b)
    if len(t) < 8:
        return ""
    if _BIN_RE.fullmatch(b):
        return "bin"
    if _HEX_RE.fullmatch(t) and len(t) % 2 == 0:
        return "hex"
    if _DEC_RE.fullmatch(b.strip()):
        return "dec"
    if _MORSE_RE.fullmatch(b) and b"." in b and b"-" in b:
        return "morse"
    if _B32_RE.fullmatch(t):
        return "b32"
    if _B64_RE.fullmatch(t) and len(t.rstrip(b"=")) % 4 != 1:
        return "b64"
    return ""


# ---------------------------------------------------------------------------
# декодеры: bytes -> [(имя, bytes, строгий?)]
# ---------------------------------------------------------------------------

def _strip_ws(b: bytes) -> bytes:
    return re.sub(rb"\s+", b"", b)


def strict_ops(b: bytes):
    out = []
    s = _strip_ws(b)
    # base64 / base64url
    core = s.rstrip(b"=")
    if len(core) >= 4 and len(core) % 4 != 1:
        padded = core + b"=" * (-len(core) % 4)
        if _B64_RE.fullmatch(s):
            try:
                out.append(("base64", base64.b64decode(padded, validate=True), True))
            except (binascii.Error, ValueError):
                pass
        elif _B64URL_RE.fullmatch(s):
            try:
                out.append(("base64url", base64.urlsafe_b64decode(padded), True))
            except (binascii.Error, ValueError):
                pass
    # base32 (регистр не важен)
    up = s.upper()
    core32 = up.rstrip(b"=")
    if len(core32) >= 8 and _B32_RE.fullmatch(up) and len(core32) % 8 in (0, 2, 4, 5, 7):
        try:
            out.append(("base32", base64.b32decode(core32 + b"=" * (-len(core32) % 8)), True))
        except (binascii.Error, ValueError):
            pass
    # hex: 0x41 0x42 / \x41\x42 / 41:42 / 4142
    h = re.sub(rb"(?i)0x|\\x|[\s:,]", b"", b)
    if len(h) >= 2 and len(h) % 2 == 0 and _HEX_RE.fullmatch(h):
        try:
            out.append(("hex", binascii.unhexlify(h), True))
        except (binascii.Error, ValueError):
            pass
    # двоичный: 01000011 01010100 ...
    if _BIN_RE.fullmatch(b):
        bits = _strip_ws(b)
        groups = b.split()
        if len(bits) >= 8 and len(bits) % 8 == 0:
            out.append(("bin", int(bits, 2).to_bytes(len(bits) // 8, "big"), True))
        elif len(groups) >= 2 and all(len(g) == 7 for g in groups):
            out.append(("bin7", bytes(int(g, 2) for g in groups), True))
    # десятичные/восьмеричные коды
    if _DEC_RE.fullmatch(b.strip()):
        nums = [int(x) for x in re.findall(rb"\d+", b)]
        if all(n <= 255 for n in nums):
            out.append(("dec", bytes(nums), True))
    if _OCT_RE.fullmatch(b.strip()):
        vals = [int(x, 8) for x in re.findall(rb"[0-7]{3}", b)]
        if all(v <= 255 for v in vals):
            out.append(("oct", bytes(vals), True))
    # url
    if re.search(rb"%[0-9a-fA-F]{2}", b):
        out.append(("url", urllib.parse.unquote_to_bytes(b), True))
    # сжатие по сигнатуре
    try:
        if b[:2] in (b"\x78\x01", b"\x78\x5e", b"\x78\x9c", b"\x78\xda"):
            out.append(("zlib", zlib.decompressobj().decompress(b, MAX_NODE), True))
        elif b[:2] == b"\x1f\x8b":
            out.append(("gzip", zlib.decompressobj(31).decompress(b, MAX_NODE), True))
        elif b[:3] == b"BZh":
            out.append(("bz2", bz2.BZ2Decompressor().decompress(b, MAX_NODE), True))
        elif b[:6] == b"\xfd7zXZ\x00":
            out.append(("xz", lzma.LZMADecompressor().decompress(b, MAX_NODE), True))
    except (zlib.error, OSError, EOFError, lzma.LZMAError, ValueError):
        pass
    # base85/ascii85: алфавит широкий — строгим считаем только читаемый результат
    if len(s) >= 5:
        for name, fn in (("base85", base64.b85decode), ("ascii85", _a85)):
            if name == "base85" and not _B85_RE.fullmatch(s):
                continue
            try:
                raw = fn(s)
            except (ValueError, binascii.Error):
                continue
            if raw:
                out.append((name, raw, printable_ratio(raw) >= 0.9))
    return out


def _a85(s: bytes) -> bytes:
    if s.startswith(b"<~"):
        return base64.a85decode(s, adobe=True)
    return base64.a85decode(s)


B64_CHARS = LETTERS + b"0123456789+/=\r\n"


def xor_best(b: bytes, top: int = 3, narrow_only: bool = False):
    """Лучшие однобайтовые XOR-ключи для промежуточного слоя.

    Оценка — quality() по первым XOR_SAMPLE байтам плюс бонус, если весь
    результат в алфавите base64/hex: у короткого блоба «печатных» ключей
    много, а вот «весь в узком алфавите» — единицы, и среди них правильный.
    narrow_only: только такие ключи (для узлов, которые уже читаемы).
    """
    sample = b[:XOR_SAMPLE]
    n = len(sample)
    if not n:
        return []
    scored = []
    for k in range(1, 256):
        t = sample.translate(XOR_TABLES[k])
        narrow = count_in(t, B64_CHARS) == n
        if narrow_only and not narrow:
            continue
        if not narrow and count_in(t, PRINTABLE) < 0.85 * n:
            continue
        sc = quality(t) + (1.0 if narrow else 0.0)
        if narrow:
            # взгляд на шаг вперёд: XOR часто лежит прямо над hex/двоичным,
            # иногда через ROT13/Atbash — такой ключ почти наверняка верный
            for v in (t, t.translate(ROT_TABLES[13]), t.translate(ATBASH)):
                if narrow_shape(v) in ("bin", "hex", "dec"):
                    sc += 1.5
                    break
        scored.append((sc, k))
    scored.sort(reverse=True)
    return [(f"xor:0x{k:02x}", b.translate(XOR_TABLES[k])) for _, k in scored[:top]]


def xor_flag_keys(b: bytes):
    """Однобайтовые ключи, после которых в b есть настоящий флаг.

    Быстрый фильтр (всё на C: translate/lower/in): в данных должны быть
    байты '{'^k и '}'^k, а после XOR — «префикс{» без учёта регистра;
    регулярка find_flags — только для прошедших фильтр ключей.
    """
    if not b or len(b) > MAX_NODE:
        return []
    have = set(b)
    any_prefix = os.environ.get("FLAG_ANY") == "1"
    if any_prefix and len(b) > 4096:
        return []
    pres = [(p.lower() + "{").encode() for p in common.prefixes()]
    out = []
    for k in range(1, 256):
        if (0x7B ^ k) not in have or (0x7D ^ k) not in have:
            continue
        t = b.translate(XOR_TABLES[k])
        if not any_prefix:
            low = t.lower()
            if not any(p in low for p in pres):
                continue
        if real_flags(t):
            out.append((f"xor:0x{k:02x}", t))
            break
    return out


def xor_known(b: bytes):
    """XOR с ключом 2–4 байта, восстановленным по префиксу флага в начале.

    Ключ длиной с сам префикс «подгоняется» под любые данные — в переборе
    тысяч узлов это даёт ложные флаги. Поэтому берём только ключи, которые
    префикс перепроверяет минимум двумя лишними символами, и читаемый итог.
    (Однобайтовый XOR — в xor_flag_keys/xor_best.)
    """
    out = []
    if len(b) < 6:
        return out
    seen = set()
    for p in common.prefixes():
        for v in dict.fromkeys((p, p.lower(), p.upper(), p.capitalize())):
            known = (v + "{").encode()
            if len(known) > len(b):
                continue
            for klen in range(2, min(4, len(known) - 2) + 1):
                key = bytes(b[i] ^ known[i] for i in range(klen))
                if key in seen or any(b[i] ^ key[i % klen] != known[i]
                                      for i in range(klen, len(known))):
                    continue
                seen.add(key)
                plain = bytes(c ^ key[i % klen] for i, c in enumerate(b[:MAX_NODE]))
                if printable_ratio(plain) >= 0.9:
                    out.append((f"xor-key:{key.hex()}", plain))
    return out[:4]


def weak_ops(b: bytes):
    out = []
    p = printable_ratio(b)
    letters = count_in(b, LETTERS)
    if letters:
        out.append(("rot13", b.translate(ROT_TABLES[13])))
        out.append(("atbash", b.translate(ATBASH)))
        if p >= 0.9 and letters >= 4:
            shifts = []
            for n in range(1, 26):
                if n == 13:
                    continue
                t = b.translate(ROT_TABLES[n])
                sc = count_in(t, FREQ) + (50 if _FLAGSHAPE.search(t) else 0)
                shifts.append((sc, n, t))
            shifts.sort(reverse=True)
            for _, n, t in shifts[:2]:
                out.append((f"rot{n}", t))
    if p >= 0.9:
        out.append(("rot47", b.translate(ROT47)))
    out.append(("reverse", b[::-1]))
    if p < 0.9:
        out.append(("not", b.translate(XOR_TABLES[255])))
    if p < 0.97:
        out.extend(xor_best(b, top=4))
    else:
        out.extend(xor_best(b, top=6, narrow_only=True))
    out.extend(xor_known(b))
    return [(n, d, False) for n, d in out]


def text_ops(b: bytes, root: bool = False):
    """Все декодеры enc.py для текстового узла (их там больше, чем здесь).

    enc.try_all медленный на длинном тексте, поэтому для промежуточных узлов
    только до TEXT_OPS_NODE символов; корень — до TEXT_OPS_LIMIT (как enc).
    """
    limit = TEXT_OPS_LIMIT if root else TEXT_OPS_NODE
    if _enc is None or len(b) > limit or printable_ratio(b) < 0.85:
        return []
    try:
        text = b.decode("utf-8")
    except UnicodeDecodeError:
        return []
    out = []
    try:
        for name, val in _enc.try_all(text):
            # ROT13/ROT47/Atbash/реверс уже есть свои (байтовые) — не плодить дубли
            if name in ENC_DUPES or name.endswith("+reverse"):
                continue
            if isinstance(val, str) and val and val != text:
                out.append((f"enc:{name}", val.encode("utf-8", "replace"), False))
    except Exception:
        return []
    return out


ENC_DUPES = {"rot13", "rot47", "atbash", "reverse"}


# --- UTF-16 внутри бинарника ------------------------------------------------
# ID3-теги mp3, ресурсы Windows, кусты реестра, часть игр хранят текст в
# UTF-16. Байтовый декодер такого не видит: половина байтов нулевая, доля
# печатных символов низкая, ни один текстовый слой не срабатывает. Поэтому
# ищем «прогоны» UTF-16 прямо в байтах: младший байт печатный, старший 0x00
# (латиница) или 0x04 (кириллица).
UTF16_LE_RE = re.compile(rb"(?:[\x20-\x7e\t\r\n][\x00\x04]){6,}")
UTF16_BE_RE = re.compile(rb"(?:[\x00\x04][\x20-\x7e\t\r\n]){6,}")


def utf16_ops(b: bytes, limit: int = 8):
    """Куски UTF-16LE/BE текста внутри бинарных данных."""
    out = []
    sample = b[:4 * 1024 * 1024]
    for name, rx, enc in (("utf16le", UTF16_LE_RE, "utf-16-le"),
                          ("utf16be", UTF16_BE_RE, "utf-16-be")):
        for m in list(rx.finditer(sample))[:limit]:
            try:
                txt = m.group(0).decode(enc)
            except UnicodeDecodeError:
                continue
            raw = txt.encode("utf-8", "replace")
            if raw:
                out.append((name, raw, False))
    return out


# base64/hex, вшитые ВНУТРЬ бинарника: в png после IEND, в pdf-комментарии,
# в JSON-логе полем "blob". Тот же принцип, что с UTF-16: детектор ищет
# прогон символов нужного алфавита, а не декодирует файл целиком.
B64_RUN_RE = re.compile(rb"[A-Za-z0-9+/]{32,}={0,2}")
HEX_RUN_RE = re.compile(rb"(?:[0-9a-fA-F]{2}){16,}")


def run_ops(b: bytes, limit: int = 6):
    """Декодировать base64/hex-прогоны, найденные внутри файла."""
    out = []
    sample = b[:2 * 1024 * 1024]
    for name, rx in (("emb:b64", B64_RUN_RE), ("emb:hex", HEX_RUN_RE)):
        for m in list(rx.finditer(sample))[:limit]:
            run = m.group(0)
            try:
                if name.endswith("b64"):
                    raw = base64.b64decode(run + b"=" * (-len(run) % 4), validate=False)
                else:
                    raw = bytes.fromhex(run.decode("ascii"))
            except (binascii.Error, ValueError):
                continue
            if len(raw) >= 8:
                out.append((name, raw, False))
    return out


COMPRESS_MAGIC = (
    (b"\x1f\x8b", "gzip"),
    (b"\xfd7zXZ\x00", "xz"),
    (b"BZh", "bz2"),
    (b"\x78\x9c", "zlib"),
    (b"\x78\x01", "zlib"),
    (b"\x78\xda", "zlib"),
    (b"PK\x03\x04", "zip"),
)


def _unzip_items(b: bytes, limit: int = 3):
    """Содержимое записей zip-архива (без пароля)."""
    import io
    import zipfile
    out = []
    try:
        with zipfile.ZipFile(io.BytesIO(b)) as zf:
            for info in zf.infolist()[:limit]:
                if info.flag_bits & 1:      # шифрованная запись — не наша
                    continue
                if 0 < info.file_size <= 4 * 1024 * 1024:
                    out.append((f"zip:{info.filename}", zf.read(info), False))
    except Exception:
        return []
    return out


def compress_ops(b: bytes, limit: int = 4 * 1024 * 1024):
    """Распаковка контейнеров: gzip/xz/bz2/zlib.

    Без этого «матрёшка» (файл в файле в файле) не разворачивается: chain
    умел только кодировки, а сжатие оставлял другим инструментам.
    """
    out = []
    for magic, kind in COMPRESS_MAGIC:
        if not b.startswith(magic):
            continue
        if kind == "zip":
            out.extend(_unzip_items(b))
            break
        try:
            if kind == "gzip":
                dec = gzip.decompress(b)
            elif kind == "xz":
                dec = lzma.decompress(b)
            elif kind == "bz2":
                dec = bz2.decompress(b)
            else:
                dec = zlib.decompress(b)
        except Exception:
            continue
        if 0 < len(dec) <= limit:
            out.append((kind, dec, False))
        break
    return out


def peel(data: bytes, max_layers: int = 12, limit: int = 8 * 1024 * 1024):
    """Последовательно снять слои: gzip/xz/bz2/zlib/zip/base64/hex/utf16.

    Матрёшка — это не поиск, а именно последовательность: каждый слой
    однозначен. Beam-поиск со скорингом тут мешает (бинарный промежуточный
    слой получает низкий score и отбрасывается), поэтому для вложенных
    контейнеров есть отдельный прямой проход.
    """
    layers = []
    cur = data
    for _ in range(max_layers):
        nxt, op = None, None
        for magic, kind in COMPRESS_MAGIC:
            if cur.startswith(magic):
                if kind == "zip":
                    items = _unzip_items(cur, limit=1)
                    if items:
                        op, nxt = items[0][0], items[0][1]
                else:
                    try:
                        if kind == "gzip":
                            nxt = gzip.decompress(cur)
                        elif kind == "xz":
                            nxt = lzma.decompress(cur)
                        elif kind == "bz2":
                            nxt = bz2.decompress(cur)
                        else:
                            nxt = zlib.decompress(cur)
                        op = kind
                    except Exception:
                        nxt = None
                break
        if nxt is None:
            s = cur.strip()
            if 8 <= len(s) <= 2_000_000 and len(s) % 4 in (0, 2, 3) and \
                    _B64_RE.fullmatch(s) and not s.startswith(b"\x89"):
                try:
                    dec = base64.b64decode(s + b"=" * (-len(s) % 4), validate=False)
                    if dec and dec != cur:
                        op, nxt = "base64", dec
                except Exception:
                    pass
            if nxt is None and 8 <= len(s) <= 2_000_000 and len(s) % 2 == 0 and \
                    re.fullmatch(rb"[0-9a-fA-F]+", s):
                try:
                    dec = bytes.fromhex(s.decode())
                    if dec:
                        op, nxt = "hex", dec
                except Exception:
                    pass
            if nxt is None:
                # base64/hex внутри текста («hint: decode me» + блоб)
                for rx, name in ((B64_RUN_RE, "emb:base64"), (HEX_RUN_RE, "emb:hex")):
                    best = max(rx.finditer(s), key=lambda m: len(m.group(0)), default=None)
                    if best is None or len(best.group(0)) < 40:
                        continue
                    run = best.group(0)
                    try:
                        dec = (base64.b64decode(run + b"=" * (-len(run) % 4))
                               if name.endswith("base64") else bytes.fromhex(run.decode()))
                    except Exception:
                        continue
                    if dec:
                        op, nxt = name, dec
                        break
            if nxt is None and len(cur) >= 16 and cur[1] == 0 and cur[0] != 0:
                try:
                    op, nxt = "utf16le", cur.decode("utf-16-le").encode("utf-8")
                except Exception:
                    nxt = None
        if nxt is None or len(nxt) > limit or not nxt:
            break
        layers.append({"op": op, "size": len(nxt)})
        cur = nxt
        flags = real_flags(cur)
        if flags and len(layers) > 0:
            layers[-1]["flags"] = flags
            break
    return layers, cur


def expand(b: bytes, root: bool = False):
    return (strict_ops(b) + compress_ops(b) + utf16_ops(b) + run_ops(b)
            + weak_ops(b) + text_ops(b, root))


def finishers(b: bytes):
    """Дешёвый взгляд «на шаг вперёд»: последний слой часто XOR."""
    return xor_flag_keys(b) + xor_known(b)


# ---------------------------------------------------------------------------
# поиск
# ---------------------------------------------------------------------------

class Result:
    def __init__(self):
        self.flag = None
        self.flags = []
        self.path = []
        self.data = b""
        self.others = []        # [(score, path, flag)] — другие объяснения
        self.best = []          # [(quality, path, data)] — читаемые кандидаты
        self.nodes = 0
        self.depth = 0
        self.stopped = ""


def _digest(b: bytes) -> bytes:
    return hashlib.blake2b(b, digest_size=16).digest()


_LEET = str.maketrans("0134578@$9", "oieastbasg")
_BIGRAMS = set("th he in er an re on at en nd ti es or te of ed is it al ar st to "
               "nt ng se ha as ou io le ve co me de hi ri ro ic ne ea ra ce li ch "
               "ll be ma si om ur ca el ta la ns ge ly ei os no pe do".split())


def _family(op: str) -> str:
    """Семейство операции: два подряд из одного семейства — лишний слой."""
    if op.startswith("xor:"):
        return "xor"
    if re.fullmatch(r"rot\d+", op):
        return "rot"
    if op in ("reverse", "atbash", "not", "rot47"):
        return op
    return ""


# априорная «цена» редких слоёв: при равной правдоподобности флага
# побеждает путь с привычными слоями (ROT13 встречается чаще Atbash)
OP_COST = {"atbash": 0.25, "rot-n": 0.3, "rot47": 0.1, "not": 0.05, "reverse": 0.05}


def path_cost(path) -> float:
    cost = 0.05 * len(path)
    for op in path:
        if op == "rot13":
            continue
        if op.startswith("enc:"):
            # enc:rot18 / enc:2sym(...) и т.п. — редкие слои, enc:base58 — обычный
            cost += 0.3 if re.match(r"enc:(rot\d|2sym|nfkc|utf8-)", op) else 0.02
            continue
        fam = "rot-n" if re.fullmatch(r"rot\d+", op) else _family(op)
        cost += OP_COST.get(fam, 0.0)
    return cost


def flag_plausibility(flag: str, layers: int = 0) -> float:
    """Насколько флаг похож на настоящий: слова/leet, чистый алфавит, гласные.

    Нужна, когда цепочка неоднозначна: «base64→hex→XOR» и
    «base64→hex→ROT13→XOR» могут дать два разных валидных флага — ROT13
    меняет только буквы, и XOR без него даёт «почти флаг» с переставленными
    буквами. Тогда выбираем более осмысленный, при равенстве — короче путь.
    """
    inner = flag[flag.find("{") + 1:-1]
    if not inner:
        return -10.0
    # пунктуация внутри флага редка, а у «почти флага» она почти всегда есть:
    # штраф за каждый такой символ, а не за долю (длинный флаг не спасает)
    clean = sum(c.isalnum() or c == "_" for c in inner) / len(inner)
    dirty = sum(0.0 if (c.isalnum() or c == "_") else 0.25 if c in "-!?" else 0.5
                for c in inner)
    # числа и id-хвосты (…_6030, …_a494, f99) — не слова: leet их только
    # зашумит; leet-словом считаем токен с цифрами и хотя бы тремя буквами
    tokens = [t for t in re.split(r"[^A-Za-z0-9]+", inner.lower())
              if t and (not re.search(r"\d", t) or len(re.findall(r"[a-z]", t)) >= 3)]
    low = " ".join(tokens).translate(_LEET)
    words = re.findall(r"[a-z]+", low)
    pairs = [w[i:i + 2] for w in words for i in range(len(w) - 1)]
    bigram = sum(p in _BIGRAMS for p in pairs) / max(1, len(inner) - 1)
    letters = "".join(words)
    if letters:
        v = sum(c in "aeiou" for c in letters) / len(letters)
        vowels = max(0.0, 1.0 - abs(v - 0.38) * 2.5)
    else:
        vowels = 0.0
    return 2.0 * bigram + 2.0 * clean - dirty + 0.5 * vowels - 0.05 * layers


def search(data: bytes, depth: int = 6, beam: int = 30, strict_beam: int = 24,
           max_nodes: int = 20000, time_limit: float = 20.0) -> Result:
    """Beam search по цепочкам декодеров до настоящего флага.

    Флаг на глубине 0–1 (то, что видит enc) принимается сразу. Флаг глубже
    может оказаться «почти флагом» (см. flag_plausibility), поэтому поиск
    доходит ещё один уровень, собирает все флаги и берёт самый правдоподобный.
    """
    res = Result()
    deadline = time.time() + max(0.5, time_limit)
    # перевод строки в конце файла срезаем только у чистого текста: у бинарного
    # блоба (и у XOR-текста) \t/\n/пробел по краям — это данные
    root = data[:MAX_ROOT]
    if root.strip(b"\r\n") and count_in(root, PRINTABLE) == len(root):
        root = root.strip(b"\r\n")
    seen = {_digest(root)}
    found = []                  # [(score, path, blob, flags)]
    grace = [None]              # последний уровень, который ещё досматриваем

    def hit(path, blob, level):
        flags = real_flags(blob)
        if not flags:
            return False
        if len(path) <= 1:
            res.flag, res.flags, res.path, res.data = flags[0], flags, path, blob
            return True
        # тысячи преобразований большого блоба рано или поздно дают случайное
        # «npc{//0Erpb}» — глубокий флаг должен быть похож на флаг
        inner = flags[0][flags[0].find("{") + 1:-1]
        plaus = flag_plausibility(flags[0])
        if len(inner) < DEEP_MIN_INNER or plaus < DEEP_MIN_PLAUS:
            return False
        # пробел внутри (find_flags отдаёт его как '_'/'') — тоже признак мусора
        spaces = max(f.count(" ") for f in flags)
        score = plaus - path_cost(path) - 0.5 * spaces
        found.append((score, path, blob, flags))
        if grace[0] is None:
            grace[0] = level + 1
        return False

    if hit([], root, 0):
        return res
    for name, d in finishers(root):
        if hit([name], d, 0):
            return res
    best = []
    frontier = [(quality(root), [], root)]
    for level in range(1, max(1, depth) + 1):
        res.depth = level
        strict_kids, weak_kids = [], []
        for _q, path, node in frontier:
            last = _family(path[-1]) if path else ""
            for name, child, strict in expand(node, root=not path):
                if len(child) < 2 or len(child) > MAX_NODE:
                    continue
                if last and _family(name) == last:
                    continue        # xor∘xor = xor, rot∘rot = rot, reverse∘reverse = id
                dg = _digest(child)
                if dg in seen:
                    continue
                seen.add(dg)
                res.nodes += 1
                cpath = path + [name]
                if hit(cpath, child, level):
                    return res
                for fname, fd in finishers(child):
                    if _family(fname) and _family(fname) == _family(name):
                        continue
                    if hit(cpath + [fname], fd, level):
                        return res
                q = quality(child)
                # слабое преобразование дало hex/двоичный/десятичный текст —
                # это почти наверняка осмысленный слой: в квоту строгих
                if not strict and narrow_shape(child) in ("bin", "hex", "dec", "morse"):
                    strict = True
                (strict_kids if strict else weak_kids).append((q, cpath, child))
                if printable_ratio(child) >= 0.9 and not real_flags(child):
                    best.append((q, cpath, child))
                if res.nodes >= max_nodes:
                    res.stopped = "nodes"
                    break
                if time.time() >= deadline:
                    res.stopped = "time"
                    break
            if res.stopped:
                break
        best.sort(key=lambda x: -x[0])
        del best[50:]
        if res.stopped or (grace[0] is not None and level >= grace[0]):
            break
        strict_kids.sort(key=lambda x: -x[0])
        weak_kids.sort(key=lambda x: -x[0])
        frontier = strict_kids[:strict_beam] + weak_kids[:beam]
        if not frontier:
            break
    res.best = best
    if found:
        found.sort(key=lambda x: -x[0])
        _sc, res.path, res.data, res.flags = found[0]
        res.flag = res.flags[0]
        seen_flags = {res.flag}
        for sc, p, _b, fl in found[1:]:
            if fl[0] not in seen_flags:
                seen_flags.add(fl[0])
                res.others.append((sc, p, fl[0]))
    return res


def describe(path) -> str:
    return " → ".join(path) if path else "как есть"


def show(b: bytes, limit: int = 300) -> str:
    return b.decode("utf-8", "replace")[:limit].replace("\r", "\\r").replace("\n", "\\n")


def main():
    ap = argparse.ArgumentParser(description="многослойные цепочки кодировок до флага")
    ap.add_argument("target", nargs="?", help="строка или путь к файлу")
    ap.add_argument("--file", help="прочитать данные из файла")
    ap.add_argument("--peel", action="store_true",
                    help="снимать слои последовательно (матрёшка)")
    ap.add_argument("--depth", type=int, default=6, help="максимум слоёв (6)")
    ap.add_argument("--beam", type=int, default=30, help="ширина луча (30)")
    ap.add_argument("--strict-beam", type=int, default=24,
                    help="квота для строгих декодеров на уровень (24)")
    ap.add_argument("--max-nodes", type=int, default=20000, help="бюджет узлов")
    ap.add_argument("--time", type=float, default=20, help="бюджет, сек (20)")
    ap.add_argument("--top", type=int, default=5, help="сколько кандидатов показать без флага")
    common.add_flag_args(ap)
    args = ap.parse_args()
    common.apply_flag_args(args)
    if args.any_prefix:
        os.environ["FLAG_ANY"] = "1"

    if args.peel:
        data = common.read_bytes(args.file or args.target)
        layers, final = peel(data)
        print(f"[+] слоёв снято: {len(layers)}")
        for i, l in enumerate(layers, 1):
            print(f"   {i:02d}. {l['op']:8s} → {l['size']} байт"
                  + (f"  флаг: {l['flags'][0]}" if l.get('flags') else ""))
        flags = real_flags(final)
        if flags:
            print(f"[+] ФЛАГ: {flags[0]}")
            return 0
        print("[-] флага нет; хвост:")
        print("    " + show(final, 200))
        return 1

    path = args.file or (args.target if args.target and os.path.isfile(args.target) else None)
    if path:
        try:
            with open(path, "rb") as f:
                data = f.read(MAX_ROOT + 1)
        except (FileNotFoundError, IsADirectoryError, PermissionError, OSError) as e:
            print(f"[-] не могу прочитать {path}: {e.__class__.__name__}")
            sys.exit(1)
        if len(data) > MAX_ROOT:
            print(f"[i] беру первые {MAX_ROOT // 1024} КБ")
    elif args.target:
        data = args.target.encode("utf-8", "surrogateescape")
    else:
        ap.error("нужна строка или файл (позицией или --file)")

    t0 = time.time()
    res = search(data, args.depth, args.beam, args.strict_beam, args.max_nodes, args.time)
    took = time.time() - t0
    if res.flag:
        print(f"[+] цепочка ({len(res.path)} слоёв): {describe(res.path)}")
        print(f"[{' > '.join(res.path) or 'raw'}] {show(res.data)}")
        print(f"[+] ФЛАГ: {res.flag}")
        # другие объяснения той же строки — строками [?], solve их не берёт
        for _sc, p, fl in res.others[:3]:
            print(f"[?] менее вероятный вариант ({describe(p)}): {fl}")
        print(f"[i] узлов: {res.nodes}, глубина: {res.depth}, {took:.1f} с")
        return
    print(f"[-] флаг не найден: узлов {res.nodes}, глубина {res.depth}, {took:.1f} с"
          + (f" (стоп: {res.stopped})" if res.stopped else ""))
    shown = 0
    for q, cpath, blob in res.best:
        if shown >= args.top:
            break
        print(f"[{' > '.join(cpath)}] {show(blob, 200)}")
        shown += 1
    if not shown:
        print("    читаемых вариантов нет: попробуй --depth 8 --beam 60 или enc/autocrack")


if __name__ == "__main__":
    main()
