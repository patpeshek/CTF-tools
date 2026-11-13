#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
common.py — общие helpers: флаги, декодирование, определение типа, вывод.

Используется новыми скриптами; старые продолжают работать автономно.
"""
from __future__ import annotations

import base64
import binascii
import json
import os
import re
import sys
import urllib.parse

FLAG_CONTENT = r"[^\x00-\x1f{}]{1,300}"
DEFAULT_PREFIXES = ["ctf", "flag", "nto", "innopolis", "innoctf", "vosh", "npc",
                    "uaz"]
CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "flags.json")


def setup_stdio():
    """UTF-8 на stdout/stderr: вывод в pipe/файл не должен падать на —, →, «», █."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass


setup_stdio()


def load_flag_sets(path=CONFIG_PATH):
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def build_flag_regex(prefixes=None, any_prefix=False):
    """Регулярка ловит ПОЛНОЕ слово-префикс перед `{` (не обрезая его до
    известной подстроки: picoCTF не должен превращаться в CTF) и любую
    непустую внутренность без управляющих символов и скобок — в том числе
    не-ASCII (кириллица) и символы вроде `+ = < > ~ |`. Решение «настоящий
    ли это флаг» принимает find_flags по _PREFIXES и _ANY_PREFIX, а не regex.
    Аргументы сохранены ради совместимости с вызовами."""
    word = r"[A-Za-z][A-Za-z0-9_]{1,31}"
    return re.compile(
        (r"(?<![A-Za-z0-9_])(" + word + r")\{(" + FLAG_CONTENT + r")\}").encode(),
        re.IGNORECASE)


def _from_env():
    raw = os.environ.get("FLAG_PREFIXES")
    if raw:
        return [x.strip() for x in raw.split(",") if x.strip()]
    name = os.environ.get("FLAG_SET")
    if name:
        sets = load_flag_sets()
        if name in sets:
            return sets[name]
    return None


_PREFIXES = _from_env() or DEFAULT_PREFIXES
_ANY_PREFIX = os.environ.get("FLAG_ANY") == "1"
FLAG_RE = build_flag_regex(_PREFIXES, _ANY_PREFIX)


def configure(prefixes=None, flag_set=None, any_prefix=False, path=CONFIG_PATH):
    """Переопределить набор префиксов на время запуска."""
    global _PREFIXES, FLAG_RE, _ANY_PREFIX
    if prefixes:
        _PREFIXES = list(dict.fromkeys(prefixes))
    elif flag_set:
        sets = load_flag_sets(path)
        key = flag_set
        if key not in sets:  # имя набора тоже без учёта регистра
            low = {k.lower(): k for k in sets}
            key = low.get(flag_set.lower(), "")
        _PREFIXES = sets.get(key, DEFAULT_PREFIXES)
    else:
        env = _from_env()
        _PREFIXES = env or DEFAULT_PREFIXES
    _ANY_PREFIX = bool(any_prefix)
    FLAG_RE = build_flag_regex(_PREFIXES, any_prefix)
    return _PREFIXES


def prefixes():
    return list(_PREFIXES)


def add_flag_args(ap):
    ap.add_argument("--flag-prefix", action="append", default=[],
                    help="добавить префикс флага (можно несколько)")
    ap.add_argument("--flag-set", help="имя набора из flags.json")
    ap.add_argument("--any-prefix", action="store_true",
                    help="ловить любой префикс вида word{...}")
    ap.add_argument("--flags-config", default=CONFIG_PATH, help="путь к flags.json")


def apply_flag_args(args):
    return configure(prefixes=args.flag_prefix or None,
                     flag_set=args.flag_set,
                     any_prefix=getattr(args, "any_prefix", False),
                     path=getattr(args, "flags_config", CONFIG_PATH))
PRINTABLE_RE = re.compile(rb"[\x20-\x7e]{4,}")

SIGS = [
    (b"\x89PNG\r\n\x1a\n", "PNG"),
    (b"\xff\xd8\xff", "JPEG"),
    (b"GIF87a", "GIF"),
    (b"GIF89a", "GIF"),
    (b"PK\x03\x04", "ZIP"),
    (b"\x1f\x8b", "GZIP"),
    (b"\xfd7zXZ\x00", "XZ"),
    (b"BZh", "BZ2"),
    (b"\x28\xb5\x2f\xfd", "ZSTD"),
    (b"\x04\x22\x4d\x18", "LZ4"),
    (b"7z\xbc\xaf\x27\x1c", "7Z"),
    (b"Rar!\x1a\x07", "RAR"),
    (b"%PDF", "PDF"),
    (b"\x7fELF", "ELF"),
    (b"MZ", "PE"),
    (b"\x00asm", "WASM"),
    (b"fLaC", "FLAC"),
    (b"SQLite format 3\x00", "SQLite"),
    (b"LUKS\xba\xbe", "LUKS"),
    (b"\xd4\xc3\xb2\xa1", "PCAP"),
    (b"\xa1\xb2\xc3\xd4", "PCAP"),
    (b"\x0a\x0d\x0d\x0a", "PCAPNG"),
    (b"ID3", "MP3"),
    (b"OggS", "OGG"),
    (b"RIFF", "RIFF"),
    (b"ustar", "TAR"),
    (b"{\\rtf", "RTF"),
]


def _flag_prefix_ok(prefix: str) -> bool:
    """Похож ли префикс на настоящий, а не на случайный мусор из вывода.

    Настоящие префиксы — `ctf`, `DUCTF`, `npc`, `ABC123`. Мусор вида `qm8h`
    или `ssGP_` (нижнее подчёркивание, случайные цифры внутри) отсекаем:
    иначе `xorknown`/`autocrack` останавливаются на первом же совпадении.
    """
    if prefix.lower() in {p.lower() for p in _PREFIXES}:
        return True
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9]{1,20}", prefix):
        return False
    if prefix.isalpha():
        return True
    # цифры допустимы только хвостом: ABC123, DUCTF2024
    letters = re.sub(r"\d+$", "", prefix)
    return len(letters) >= 2 and letters.isalpha()


def find_flags(data: bytes) -> list[str]:
    known_set = {p.lower() for p in _PREFIXES}
    out = []
    for m in FLAG_RE.finditer(data):
        try:
            s = m.group(0).decode("utf-8")
            prefix = m.group(1).decode("ascii")
        except UnicodeDecodeError:
            continue
        inner = s[len(prefix) + 1:-1]
        if len(inner) < 3:
            continue
        low = prefix.lower()
        # Обычный режим: слово-префикс должно совпадать с известным префиксом
        # или оканчиваться им (picoCTF, DUCTF, bcactf) — так префикс отдаётся
        # целиком, а не обрезается. --any-prefix: любой правдоподобный префикс.
        if _ANY_PREFIX:
            if not _flag_prefix_ok(prefix):
                continue
        else:
            if not (low in known_set or any(low.endswith(k) for k in known_set)):
                continue
            if not _flag_prefix_ok(prefix):
                continue
        # Внутренность: большинство символов — буквы/цифры/подчёркивание
        # (isalnum покрывает кириллицу и другие алфавиты). Символы вроде
        # + = < > ~ | допустимы, но не сплошной мусор.
        good = sum(ch.isalnum() or ch == "_" for ch in inner)
        if good / len(inner) < 0.7:
            continue
        known = low in known_set
        # флаг из PDF/текста с пробелом: исходный пробел мог быть и
        # подчёркиванием, и простым переносом строки — отдаём все варианты
        if " " in inner and (known or prefix.isalpha()):
            out.append(prefix + "{" + inner.replace(" ", "_") + "}")
            out.append(prefix + "{" + inner.replace(" ", "") + "}")
            if not known:
                # незнакомый префикс + пробелы — скорее OCR-мусор, чем флаг
                continue
        out.append(s)
    return list(dict.fromkeys(out))
    return out


_ANSI_RE = re.compile(rb"\x1b\[[0-9;?]*[A-Za-z]")
_ZW_CHARS = {0x200b, 0x200c, 0x200d, 0x200e, 0x200f, 0x2060, 0xfeff, 0x00ad}


def clean_for_flags(data: bytes) -> bytes:
    """Убрать ANSI-раскраску и невидимые символы, чтобы флаг не рвался."""
    data = _ANSI_RE.sub(b"", data)
    try:
        text = data.decode("utf-8", "replace")
    except Exception:
        return data
    if not any(ord(ch) in _ZW_CHARS for ch in text):
        return data
    return "".join(ch for ch in text if ord(ch) not in _ZW_CHARS).encode("utf-8", "replace")


class FlagGrabber:
    """Ищет флаг в потоке, даже если он пришёл кусками или в base64.

    Сервис может прислать `CTF{ab` в одном recv и `c}` в следующем, обернуть
    флаг в ANSI-цвета, вставить zero-width или отдать base64-строкой. Класс
    копит хвост, чистит его и возвращает только новые находки.
    """

    def __init__(self, tail: int = 16384):
        self.tail = tail
        self.buf = b""
        self.found: list[str] = []

    def feed(self, data: bytes) -> list[str]:
        if not data:
            return []
        self.buf = (self.buf + data)[-self.tail:]
        new: list[str] = []
        for src in (data, self.buf):
            cleaned = clean_for_flags(src)
            for f in find_flags(cleaned):
                if f not in self.found:
                    self.found.append(f)
                    new.append(f)
            # незнакомый префикс в потоке сервиса: NPC{...}, ABC_1{...}
            for m in re.finditer(rb"\b[A-Z][A-Z0-9_]{1,15}\{[ -~]{4,300}\}", cleaned):
                try:
                    cand = m.group().decode("ascii")
                except UnicodeDecodeError:
                    continue
                inner = cand[cand.find("{") + 1:-1]
                if len(inner) < 4:
                    continue
                good = sum(ch.isalnum() or ch in "_ " for ch in inner)
                if good / len(inner) < 0.7:
                    continue
                if cand not in self.found:
                    self.found.append(cand)
                    new.append(cand)
            for tok in re.findall(rb"[A-Za-z0-9+/]{16,4096}={0,2}", cleaned):
                try:
                    import base64 as _b64
                    raw = _b64.b64decode(tok + b"=" * ((4 - len(tok) % 4) % 4))
                except Exception:
                    continue
                for f in find_flags(clean_for_flags(raw)):
                    if f not in self.found:
                        self.found.append(f)
                        new.append(f)
        return new

    def feed_text(self, text: str) -> list[str]:
        return self.feed(text.encode("utf-8", "replace"))


def printable_ratio(data) -> float:
    """Доля печатных символов. Принимает bytes и str."""
    if not data:
        return 0.0
    if isinstance(data, str):
        return sum(1 for c in data if c.isprintable() or c in "\r\n\t") / len(data)
    return sum(32 <= c < 127 or c in (9, 10, 13) for c in data) / len(data)


def sniff(head: bytes) -> str:
    # TAR: магия ustar на смещении 257, а не с начала файла.
    if len(head) >= 262 and head[257:262] == b"ustar":
        return "TAR"
    for sig, name in SIGS:
        if name in ("TAR", "PE", "RIFF"):
            continue  # обрабатываются отдельно ниже
        if head.startswith(sig):
            return name
    # PE только если это действительно PE, а не текст, начинающийся с «MZ».
    if head[:2] == b"MZ" and (b"PE\x00\x00" in head[:2048]
                              or b"This program cannot be run" in head[:256]):
        return "PE"
    # RIFF-контейнеры различаем по типу: WEBP/AVI, остальное (WAVE) — RIFF.
    if head[:4] == b"RIFF" and len(head) >= 12:
        kind = head[8:12]
        if kind == b"WEBP":
            return "WEBP"
        if kind == b"AVI ":
            return "AVI"
        return "RIFF"
    # OLE2 — старые .doc/.xls/.ppt, .msi.
    if head[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        return "OLE"
    # BMP.
    if head[:2] == b"BM" and len(head) >= 6:
        return "BMP"
    # PCAP с наносекундными метками (иначе выглядит как unknown).
    if head[:4] in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"):
        return "PCAP"
    # MP3 без тега ID3 — кадровая синхронизация MPEG audio.
    if head[:2] in (b"\xff\xfb", b"\xff\xfa", b"\xff\xf3", b"\xff\xf2",
                    b"\xff\xe3", b"\xff\xe2"):
        return "MP3"
    # ISO BMFF: [4 байта размера] + ftyp + бренд (mp4/mov/m4a).
    if len(head) >= 12 and head[4:8] == b"ftyp":
        if head[8:12] in (b"isom", b"mp42", b"mp41", b"avc1", b"iso2",
                          b"qt  ", b"m4a ", b"dash", b"iso5"):
            return "MP4"
    return "unknown"


def is_text(data: bytes, threshold: float = 0.9) -> bool:
    if not data:
        return False
    sample = data[:8192]
    try:
        t = sample.decode("utf-8")
    except UnicodeDecodeError:
        t = sample.decode("latin-1")  # cp1251/кириллица: байты >=0x80 печатные
    return printable_ratio(t) >= threshold


def xor_prefix_hits(data: bytes, prefix_list=None, max_keylen: int = 16):
    """Если открытый текст начинается с префикса флага (known plaintext),
    восстановить ключ XOR и расшифровать. Возвращает [(prefix, key, plain)]."""
    out = []
    uniq = set()
    if not data or len(data) < 4:
        return out
    for pre in (prefix_list or prefixes()):
        known = (pre + "{").encode()
        if len(data) < len(known):
            continue
        for klen in range(1, min(len(known), max_keylen) + 1):
            key = bytearray(klen)
            seen = [0] * klen
            ok = True
            for i, p in enumerate(known):
                k = data[i] ^ p
                pos = i % klen
                if seen[pos] and key[pos] != k:
                    ok = False
                    break
                key[pos] = k
                seen[pos] = 1
            if not ok or not all(seen):
                continue
            plain = bytes(c ^ key[i % klen] for i, c in enumerate(data))
            if plain in uniq:
                continue
            uniq.add(plain)
            out.append((pre, bytes(key), plain))
    return out


def api_denial_note(data: bytes):
    """Если скачался JSON-отказ API вместо файла — вернуть подсказку."""
    head = data[:4096].lstrip()
    if not head.startswith((b"{", b"[")):
        return None
    try:
        obj = json.loads(head.decode("utf-8", "replace"))
    except Exception:
        return None
    blob = json.dumps(obj, ensure_ascii=False).upper()
    marks = ("ACCESS_DENIED", "ACCESS DENIED", "FORBIDDEN", "UNAUTHORIZED", "PERMISSION DENIED")
    if not any(m in blob for m in marks):
        return None
    code = ""
    if isinstance(obj, dict):
        code = str(obj.get("code") or obj.get("error") or "")[:80]
    return ("похоже на ответ API, а не на файл (%s) — файл не скачался. "
            "Открой задачу/инстанс в браузере (нужны куки) и скачай заново" % (code or "denied"))


def decode_field(s: str) -> list[tuple[str, bytes]]:
    """hex / base64 / raw — для одного поля (nonce, key, ciphertext)."""
    out = []
    t = s.strip()
    try:
        out.append(("hex", bytes.fromhex(re.sub(r"(?i)0x|[\s:]", "", t))))
    except ValueError:
        pass
    try:
        out.append(("base64", base64.b64decode(t + "=" * (-len(t) % 4))))
    except Exception:
        pass
    out.append(("raw", t.encode()))
    return out


def decode_auto(s: str) -> list[tuple[str, str]]:
    """Все разумные интерпретации строки; возвращает (как, текст)."""
    t = s.strip()
    res = []

    def add(name, val):
        if isinstance(val, bytes):
            try:
                val = val.decode("ascii")
            except UnicodeDecodeError:
                return
        if not isinstance(val, str) or not val or val == t:
            return
        if printable_ratio(val.encode("utf-8", "replace")) < 0.85:
            return
        res.append((name, val))

    try:
        add("base64", base64.b64decode(t + "=" * (-len(t) % 4)))
    except Exception:
        pass
    try:
        add("base64url", base64.urlsafe_b64decode(t + "=" * (-len(t) % 4)))
    except Exception:
        pass
    try:
        add("base32", base64.b32decode(t.upper() + "=" * (-len(t) % 8)))
    except Exception:
        pass
    try:
        add("base85", base64.b85decode(t))
    except Exception:
        pass
    try:
        h = re.sub(r"(?i)0x|[\s:]", "", t)
        add("hex", binascii.unhexlify(h + "0" * (len(h) % 2)))
    except Exception:
        pass
    if "%" in t:
        add("url", urllib.parse.unquote(t))
    add("reverse", t[::-1])
    if re.fullmatch(r"[01\s]{8,}", t):
        bits = re.sub(r"\s", "", t)
        add("binary", "".join(chr(int(bits[i:i + 8], 2)) for i in range(0, len(bits) - 7, 8)))
    if re.fullmatch(r"[\d\s,;]+", t):
        nums = [int(x) for x in re.findall(r"\d+", t)]
        if all(0 <= n <= 0x10FFFF for n in nums):
            add("dec->chr", "".join(chr(n) for n in nums))
    return res


def strings(data: bytes, minlen: int = 4, limit: int = 200):
    out = []
    for m in PRINTABLE_RE.finditer(data):
        s = m.group()
        if len(s) >= minlen:
            out.append((m.start(), s.decode("utf-8", "replace")))
            if len(out) >= limit:
                break
    return out


def read_bytes(path: str) -> bytes:
    if path == "-":
        return sys.stdin.buffer.read()
    return open(path, "rb").read()


def human(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.0f} B"


def classify_text(text: str):
    """Что за текст: whitespace-only, zero-width, braille, эзотерика, кодировки."""
    tags = []
    if not text:
        return tags
    if text.lstrip()[:5].lower() == "{\\rtf":
        tags.append("rtf")
    if all(c in " \t\r\n" for c in text):
        tags.append("whitespace-only")
    zw = sum(c in "\u200b\u200c\u200d\u2060\ufeff" for c in text)
    if zw:
        tags.append(f"zero-width:{zw}")
    vs = sum(0xFE00 <= ord(c) <= 0xFE0F for c in text)
    if vs:
        tags.append(f"variation-selectors:{vs}")
    br = sum(0x2800 <= ord(c) <= 0x28FF for c in text)
    if br:
        tags.append(f"braille:{br}")
    if any(line != line.rstrip(" \t") for line in text.splitlines()):
        tags.append("trailing-whitespace")
    body = "".join(c for c in text if not c.isspace())
    if body and set(body) <= set("+-<>[].,"):
        tags.append("esolang:brainfuck")
    if "Ook" in text:
        tags.append("esolang:ook")
    if any(k in text for k in ("MoO", "MOo", "moO", "mOo")):
        tags.append("esolang:cow")
    if body and set(body) <= set("idso"):
        tags.append("esolang:deadfish")
    if any(c in text for c in ("@", "<", ">", "^", "v")) and "\n" in text and \
            sum(c in "<>^v@\"_|$#.,:gp&~" for c in body) > len(body) * 0.2:
        tags.append("esolang:befunge?")
    if re.search(r"(?:[0-9a-fA-F]{32,}|[A-Za-z0-9+/]{32,}={0,2})", text):
        tags.append("encoded-blob")
    return tags


# ---------------- RTF ----------------

_RTF_SKIP_DESTS = {
    "fonttbl", "colortbl", "stylesheet", "info", "pict", "object", "header",
    "headerl", "headerr", "headerf", "footer", "footerl", "footerr", "footerf",
    "footnote", "annotation", "field", "fldinst", "themedata", "colorschememapping",
    "latentstyles", "datastore", "xmlnstbl", "listtable", "listoverridetable",
    "rsidtbl", "generator", "expandedcolortbl", "filetbl", "revtbl", "pnseclvl",
    "listtext", "bkmkstart", "bkmkend", "template", "mmathPr",
}


def is_rtf(data: bytes) -> bool:
    head = data.lstrip()[:6].lower()
    return head.startswith(b"{\\rtf")


def rtf_to_text(data: bytes, keep_layout: bool = False) -> str:
    """RTF → читаемый текст.

    Убирает управляющие слова и служебные группы (шрифты, цвета, картинки),
    разворачивает \\'hh (cp1251/ansi), \\uNNNN и \\tab / \\par / \\line.

    keep_layout=True — сохранить переводы строк исходного RTF и пробелы
    (нужно, когда данные спрятаны в «хвостовых» пробелах, а не в тексте).
    """
    text = data.decode("latin-1")
    out = []
    stack = []          # прежнее значение skip на каждый уровень группы
    skip = False
    pending = False     # только что открыли группу — следующее слово решает
    i, n = 0, len(text)
    uc = 1              # \ucN — сколько байт-заменителей съесть после \uN
    while i < n:
        c = text[i]
        if c == "\\":
            i += 1
            if i >= n:
                break
            c2 = text[i]
            if c2 == "'":                        # \'hh — байт в текущей кодировке
                hx = text[i + 1:i + 3]
                i += 3
                if not skip:
                    try:
                        out.append(bytes([int(hx, 16)]).decode("cp1251", "replace"))
                    except ValueError:
                        pass
                continue
            if c2 == "u":                        # \uNNNN — юникод
                i += 1
                j = i
                if j < n and text[j] == "-":
                    j += 1
                while j < n and text[j].isdigit():
                    j += 1
                try:
                    val = int(text[i:j])
                    if val < 0:
                        val += 65536
                    if not skip:
                        out.append(chr(val))
                except ValueError:
                    pass
                i = j
                # пропустить байты-заменители \ucN
                for _ in range(uc):
                    while i < n and text[i] == " ":
                        i += 1
                    if i < n and text[i] not in "\\{}":
                        i += 1
                continue
            if c2 in "{}\\":                     # \{ \} \\
                if not skip:
                    out.append(c2)
                i += 1
                continue
            if c2 == "~":
                if not skip:
                    out.append("\u00a0")
                i += 1
                continue
            if c2 in "\r\n":                     # \<newline> — жёсткий перенос
                if not skip and keep_layout:
                    out.append("\n")
                i += 1
                continue
            if not c2.isalpha():                 # \- \_ \* ... — просто убрать
                i += 1
                continue
            j = i
            while j < n and text[j].isalpha():
                j += 1
            word = text[i:j].lower()
            i = j
            num = ""
            if i < n and (text[i] == "-" or text[i].isdigit()):
                k = i
                if text[k] == "-":
                    k += 1
                while k < n and text[k].isdigit():
                    k += 1
                num = text[i:k]
                i = k
            if i < n and text[i] == " ":
                i += 1
            if word == "par" or word == "line" or word == "sect" or word == "row":
                if not skip:
                    out.append("\n")
                continue
            if word == "tab":
                if not skip:
                    out.append("\t")
                continue
            if word == "uc" and num:
                try:
                    uc = int(num)
                except ValueError:
                    uc = 1
                continue
            if word in _RTF_SKIP_DESTS and pending:
                skip = True
                pending = False
                continue
            pending = False
            continue
        if c == "{":
            i += 1
            stack.append(skip)
            pending = True
            if text[i:i + 1] == "*":
                skip = True
                pending = False
                i += 1
            continue
        if c == "}":
            i += 1
            if stack:
                skip = stack.pop()
            pending = False
            continue
        if not skip:
            if c == "\n" or c == "\r":
                if keep_layout:
                    out.append(c)
            else:
                out.append(c)
        pending = False
        i += 1
    res = "".join(out)
    if not keep_layout:
        res = re.sub(r"[ \t]{2,}", " ", res)
        res = re.sub(r"[ \t]+\n", "\n", res)
        res = re.sub(r"\n{3,}", "\n\n", res)
    return res


def document_text(path: str):
    """
    Достаёт читаемый текст из документа: DOCX/XLSX (zip), PDF, обычный текст.
    Возвращает [(label, text)].
    """
    import zipfile
    out = []
    try:
        if zipfile.is_zipfile(path):
            with zipfile.ZipFile(path) as z:
                for info in z.infolist():
                    low = info.filename.lower()
                    if not low.endswith((".xml", ".txt", ".csv", ".json", ".md")):
                        continue
                    try:
                        raw = z.read(info).decode("utf-8", "replace")
                    except Exception:
                        continue
                    if low.endswith(".xml"):
                        try:
                            import xml.etree.ElementTree as ET
                            root = ET.fromstring(raw)
                            raw = "".join((el.text or "") for el in root.iter())
                        except Exception:
                            raw = re.sub(r"<[^>]+>", "", raw)
                    out.append((f"{path}!{info.filename}", raw))
            return out
        if path.lower().endswith(".pdf"):
            try:
                from pypdf import PdfReader
                r = PdfReader(path)
                for i, page in enumerate(r.pages[:50]):
                    out.append((f"{path}#p{i+1}", page.extract_text() or ""))
            except Exception:
                pass
            return out
        data = open(path, "rb").read(4_000_000)
        if is_rtf(data):
            out.append((f"{path} [текст]", rtf_to_text(data)))
            layout = rtf_to_text(data, keep_layout=True)
            if layout != out[-1][1]:
                out.append((f"{path} [с разметкой, без control-слов]", layout))
            return out
        if b"\x00" not in data[:2000]:
            out.append((path, data.decode("utf-8", "replace")))
    except Exception:
        pass
    return out


def dump_json(obj, path=None):
    text = json.dumps(obj, ensure_ascii=False, indent=2, default=str)
    if path:
        open(path, "w", encoding="utf-8").write(text)
        return path
    print(text)


def discover_plugins(folder: str | None = None):
    """Найти плагины в plugins/: модуль с словарём PLUGIN.

    PLUGIN = {
        "name": "short-name",
        "kind": "interactive" | "file",
        "match": {"banner": r"...", "file": r"...", "ext": [".pcap"]},
        "move": callable(text, state) -> str | None   # interactive
        "run":  callable(path, opts) -> dict          # file
    }
    """
    import glob
    import importlib.util

    if folder is None:
        folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), "plugins")
    out = []
    if not os.path.isdir(folder):
        return out
    for path in sorted(glob.glob(os.path.join(folder, "*.py"))):
        name = os.path.basename(path)
        if name.startswith("_"):
            continue
        try:
            spec = importlib.util.spec_from_file_location("ctfplug_" + name[:-3], path)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
        except Exception as e:  # noqa: BLE001
            out.append((path, {"name": name, "error": str(e)}))
            continue
        meta = getattr(mod, "PLUGIN", None)
        if isinstance(meta, dict) and meta.get("name"):
            meta = dict(meta)
            meta["_module"] = mod
            out.append((path, meta))
    return out


class Screen:
    """Мини-эмулятор терминала: перерисовка, \r, \b, очистка экрана.

    Нужен для игр/PPC, где сервис рисует одно окно и обновляет его ANSI-кодами,
    а не печатает новую строку на каждый вопрос.
    """

    def __init__(self, max_lines: int = 300, max_cols: int = 300):
        self.lines = [""]
        self.r = 0
        self.c = 0
        self.max_lines = max_lines
        self.max_cols = max_cols

    def _ensure(self):
        while len(self.lines) <= self.r:
            self.lines.append("")
        if len(self.lines) > self.max_lines:
            drop = len(self.lines) - self.max_lines
            self.lines = self.lines[drop:]
            self.r = max(0, self.r - drop)

    def _put(self, ch: str):
        self._ensure()
        line = self.lines[self.r]
        if self.c > len(line):
            line += " " * (self.c - len(line))
        if self.c < len(line):
            line = line[:self.c] + ch + line[self.c + 1:]
        else:
            line += ch
        self.lines[self.r] = line[:self.max_cols]
        self.c += 1

    def _csi(self, params: str, final: str):
        nums = [int(x) for x in params.replace("?", "").split(";") if x.isdigit()]
        n = nums[0] if nums else 1
        if final == "J":
            if n == 2 or not nums:
                self.lines = [""]
                self.r = self.c = 0
            else:
                self.lines[self.r] = self.lines[self.r][:self.c]
                del self.lines[self.r + 1:]
        elif final == "K":
            self._ensure()
            self.lines[self.r] = self.lines[self.r][:self.c]
        elif final == "H" or final == "f":
            self.r = (nums[0] - 1) if nums else 0
            self.c = (nums[1] - 1) if len(nums) > 1 else 0
            self._ensure()
        elif final == "A":
            self.r = max(0, self.r - n)
        elif final == "B":
            self.r += n
            self._ensure()
        elif final == "C":
            self.c += n
        elif final == "D":
            self.c = max(0, self.c - n)

    def feed(self, text: str):
        i = 0
        while i < len(text):
            ch = text[i]
            if ch == "\x1b":
                m = re.match(r"\x1b\[([0-9;?]*)([A-Za-z])", text[i:])
                if m:
                    self._csi(m.group(1), m.group(2))
                    i += m.end()
                    continue
                m2 = re.match(r"\x1b\][^\x07]*\x07", text[i:])
                if m2:
                    i += m2.end()
                    continue
                i += 1
                continue
            if ch == "\r":
                self.c = 0
            elif ch == "\n":
                self.r += 1
                self.c = 0
                self._ensure()
            elif ch == "\b":
                self.c = max(0, self.c - 1)
            elif ch == "\t":
                self.c += 8 - (self.c % 8)
            elif ch >= " ":
                self._put(ch)
            i += 1

    def text(self) -> str:
        self._ensure()
        return "\n".join(self.lines)


def render_screen(text: str, previous: "Screen | None" = None) -> str:
    """Скормить чанк экрану и вернуть текущее содержимое."""
    scr = previous or Screen()
    scr.feed(text)
    return scr.text()
