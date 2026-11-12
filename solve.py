#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
solve.py — автопилот: прогнать по артефакту всё подходящее и остановиться на флаге.

  python solve.py file.bin
  python solve.py dump/ --deep
  python solve.py "http://host/?q=0"
  python solve.py 10.0.0.5:1337
  python solve.py file.png --plan        # только показать, что будет запускать

Работает офлайн, без ИИ и без сети (кроме явных URL/сервисов). Шаги идут от
дешёвых к дорогим, после каждого вывода ищутся флаги; на первом — стоп.
Всё, что важно, печатает; модули переиспользуются как есть (subprocess),
поэтому solve ничего не дублирует.
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
import json
import os
import re
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)
import common  # noqa: E402
import toolbox  # noqa: E402


STUB_WORDS = ("missing", "placeholder", "dummy", "fake")


def real_flags(data: bytes):
    found = common.find_flags(data)
    stubs = [f for f in found if any(w in f.lower() for w in STUB_WORDS)]
    real = [f for f in found if f not in stubs]
    return real, stubs


CAND_RE = re.compile(r"(?<![A-Za-z0-9+/=])([A-Za-z0-9+/=]{16,}|[0-9a-fA-F]{16,}|[.\-]{10,})(?![A-Za-z0-9+/=])")


def harvest_candidates(runner, limit=8):
    """Строки из вывода инструментов, которые похожи на ещё один слой кодировки."""
    seen, out = set(), []
    for _, text in runner.outputs:
        for m in CAND_RE.finditer(text):
            c = m.group(1)
            if c in seen:
                continue
            if not (re.search(r"\d", c) or "+" in c or "=" in c
                    or re.fullmatch(r"[.\-]+", c) or len(c) >= 24):
                continue
            seen.add(c)
            out.append(c)
    return out[:limit]


class Runner:
    def __init__(self, budget: float, verbose: bool, log_path=None, jobs: int = 4):
        self.deadline = time.time() + budget
        self.verbose = verbose
        self.log_path = log_path
        self.steps = 0
        self.outputs = []
        self.grabs = []
        self.notes = []
        self.jobs = max(1, int(jobs))
        self._lock = threading.Lock()
        self.stop = threading.Event()

    def remaining(self) -> float:
        return max(1.0, self.deadline - time.time())

    def _say(self, msg: str):
        with self._lock:
            print(msg, flush=True)

    def run(self, name: str, args, why: str, timeout: float = 45.0):
        return self.run_many([(name, args, why, timeout)])

    def run_many(self, steps):
        """Несколько независимых шагов; при jobs>1 — параллельно, стоп на флаге."""
        if not steps:
            return None
        if self.jobs == 1:
            for step in steps:
                flag = self._one(step, None)
                if flag:
                    return flag
            return None
        idx = 0
        while idx < len(steps) and not self.stop.is_set():
            batch = steps[idx:idx + self.jobs]
            base = idx
            idx += len(batch)
            with ThreadPoolExecutor(max_workers=len(batch)) as ex:
                futs = {ex.submit(self._one, s, base + i): s for i, s in enumerate(batch)}
                for fut in as_completed(futs):
                    flag = fut.result()
                    if flag:
                        self.stop.set()
                        for f2 in futs:
                            f2.cancel()
                        return flag
        return None

    def run_serial(self, steps):
        for step in steps:
            flag = self._one(step, None)
            if flag:
                return flag
        return None

    def _one(self, step, offset):
        name, args, why, timeout = step
        path = toolbox.path_of(name)
        if not path or not os.path.exists(path):
            return None
        if time.time() >= self.deadline - 1 or self.stop.is_set():
            return None
        with self._lock:
            self.steps += 1
            num = self.steps
            limit = max(3.0, min(timeout, self.remaining()))
        self._say(f"[{num:02d}] {name:11s} — {why}")
        cmd = [sys.executable, path, *map(str, args)]
        env = {**os.environ, "PYTHONIOENCODING": "utf-8",
               "FLAG_PREFIXES": ",".join(common.prefixes())}
        try:
            r = subprocess.run(cmd, capture_output=True, timeout=limit, env=env)
        except subprocess.TimeoutExpired:
            self._say("     таймаут, пропускаю")
            return None
        out = (r.stdout + r.stderr).decode("utf-8", "replace")
        with self._lock:
            self.outputs.append((name, out))
        # строки-кандидаты (OCR-варианты, «может быть») — не подтверждённый флаг
        scan = "\n".join(
            line for line in out.splitlines()
            if not line.lstrip().startswith(("[?]", "[i]")) or "ФЛАГ" in line
        )
        flags, stubs = real_flags(scan.encode())
        if stubs and not flags:
            for s in dict.fromkeys(stubs):
                with self._lock:
                    if s in self.notes:
                        continue
                    self.notes.append(s)
                self._say(f"     [!] заглушка {s} — не флаг")
        if self.verbose:
            for line in out.splitlines()[:15]:
                self._say("     " + line[:200])
        if flags:
            uniq = list(dict.fromkeys(flags))
            self._say(f"[!!!] ФЛАГ на шаге «{name}»: {' | '.join(uniq)}")
            return uniq[0]
        # полезный текст: OCR, кадры, «почти одинаковые строки» — его надо
        # показать, иначе человек не увидит распознанный флаг
        if name in ("ocr", "video", "nearlines", "text", "enc", "exif"):
            shown = 0
            for line in out.splitlines():
                line = line.strip()
                if not line or line.startswith(("[i]", "[-]", "[+]", "[!]")):
                    continue
                self._say("     " + line[:200])
                shown += 1
                if shown >= 12:
                    break
        # зацепки без флага: PIN, кандидаты в ключи, подозрительные строки
        for line in out.splitlines():
            if re.search(r"возможный|кандидат|PIN|пароль|похоже на код", line, re.I):
                with self._lock:
                    self.grabs.append(f"{name}: {line.strip()[:160]}")
        return None

    def dump_log(self):
        if not self.log_path:
            return
        with open(self.log_path, "w", encoding="utf-8") as f:
            for name, out in self.outputs:
                f.write(f"\n===== {name} =====\n{out}\n")
        print(f"[i] лог: {self.log_path}")


def prep_docx(path):
    """Вытащить XML-части документа рядом с временем, чтобы ws мог их читать."""
    import zipfile
    out = []
    try:
        z = zipfile.ZipFile(path)
    except Exception:
        return out
    base = os.path.join(tempfile.gettempdir(), "solve_doc")
    os.makedirs(base, exist_ok=True)
    wanted = ("word/document.xml", "xl/sharedStrings.xml", "ppt/slides/slide1.xml",
              "word/footnotes.xml", "word/header1.xml")
    for name in z.namelist():
        if name not in wanted:
            continue
        dst = os.path.join(base, os.path.basename(path) + "." + name.replace("/", "_"))
        try:
            with open(dst, "wb") as f:
                f.write(z.read(name))
        except Exception:
            continue
        out.append(dst)
    return out


def prep_docx_runs(path):
    """Текст из <w:t> по одному run на строку — чтобы ws ловил хвостовые пробелы."""
    import re as _re
    import zipfile
    try:
        z = zipfile.ZipFile(path)
        xml = z.read("word/document.xml").decode("utf-8", "replace")
    except Exception:
        return None
    runs = _re.findall(r"<w:t[^>]*>(.*?)</w:t>", xml, _re.S)
    if not runs:
        return None
    base = os.path.join(tempfile.gettempdir(), "solve_doc")
    os.makedirs(base, exist_ok=True)
    dst = os.path.join(base, os.path.basename(path) + ".runs.txt")
    try:
        with open(dst, "w", encoding="utf-8") as f:
            f.write("\n".join(runs))
    except OSError:
        return None
    return dst


def read_text(path, limit=20000):
    try:
        data = open(path, "rb").read(limit)
    except OSError:
        return ""
    for enc in ("utf-8", "cp1251"):
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            continue
    return data.decode("latin-1", "replace")


HINT_RE = re.compile(r"(?i)\b(key|iv|nonce|seed|password|pass|pin|mode)\b\s*[:=]\s*[\"']?([^\s\"']{2,64})")

WORDLISTS = [
    r"F:\dev\wordlists\rockyou.txt",
    r"F:\dev\wordlists\10m-top-1000000.txt",
    r"F:\dev\wordlists\xato-10m-1000000.txt",
    r"F:\dev\wordlists\best110k.txt",
    r"F:\dev\wordlists\10k-most-common.txt",
    r"F:\dev\wordlists\probable-v2-top12000.txt",
    r"F:\dev\wordlists\darkweb2017-top10000.txt",
    r"C:\Users\nispa\.vscode\AIproject\tools\wordlists\rockyou.txt",
]


def find_wordlist():
    for p in WORDLISTS:
        if os.path.exists(p):
            return p
    return None


def hint_params(path):
    """Параметры из соседних текстовых файлов (key=..., iv=..., mode=...)."""
    d = path if os.path.isdir(path) else os.path.dirname(path) or "."
    out = {}
    try:
        names = sorted(os.listdir(d))[:200]
    except OSError:
        return out
    for n in names:
        p = os.path.join(d, n)
        if os.path.abspath(p) == os.path.abspath(path) or not os.path.isfile(p):
            continue
        if not n.lower().endswith((".txt", ".md", ".hint", ".log", ".readme")):
            continue
        try:
            if os.path.getsize(p) > 200_000:
                continue
        except OSError:
            continue
        for m in HINT_RE.finditer(read_text(p)):
            out.setdefault(m.group(1).lower(), m.group(2))
    return out


def carve_dir(path):
    return os.path.join(tempfile.gettempdir(), "solve_carve", os.path.basename(path) or "target")


ARCHIVE_KINDS = {"XZ", "BZ2", "ZSTD", "LZ4", "GZIP", "TAR", "ZIP", "7Z", "RAR"}
ARCHIVE_EXT = {".xz", ".lzma", ".bz2", ".bz", ".zst", ".zstd", ".lz4",
               ".tar", ".tgz", ".tbz2", ".txz", ".tlz", ".gz"}


def _archive_kind(path, data):
    kind = common.sniff(data[:4096]) if data else "unknown"
    if kind in ARCHIVE_KINDS:
        return kind
    ext = os.path.splitext(path)[1].lower()
    if ext in ARCHIVE_EXT:
        return {".xz": "XZ", ".lzma": "XZ", ".bz2": "BZ2", ".bz": "BZ2",
                ".zst": "ZSTD", ".zstd": "ZSTD", ".lz4": "LZ4",
                ".tar": "TAR", ".tgz": "GZIP", ".tbz2": "BZ2", ".txz": "XZ",
                ".tlz": "XZ", ".gz": "GZIP"}[ext]
    return None


def unpack_one(path):
    """Распаковать один слой (xz/bz2/gzip/zstd/lz4/tar/zip) в temp.

    Возвращает список путей. Нужно потому, что половина файловых задач
    приходит как `flag.wav.xz` / `traffic.pcapng.xz`, и без этого шага
    `solve` видит только «unknown»-архив.
    """
    import bz2
    import gzip as _gz
    import lzma
    import tarfile
    import zipfile

    data = common.read_bytes(path)
    kind = _archive_kind(path, data)
    base = os.path.join(tempfile.gettempdir(), "solve_unpack",
                        os.path.basename(path).replace(".", "_"))
    os.makedirs(base, exist_ok=True)
    out = []
    try:
        if kind == "XZ":
            raw = lzma.decompress(data)
            name = os.path.basename(path)
            for suf in (".xz", ".lzma", ".txz", ".tlz"):
                if name.lower().endswith(suf):
                    name = name[: -len(suf)]
                    break
            dst = os.path.join(base, name or "unpacked.bin")
            open(dst, "wb").write(raw)
            out.append(dst)
        elif kind == "BZ2":
            raw = bz2.decompress(data)
            name = os.path.basename(path)
            for suf in (".bz2", ".bz", ".tbz2"):
                if name.lower().endswith(suf):
                    name = name[: -len(suf)]
                    break
            dst = os.path.join(base, name or "unpacked.bin")
            open(dst, "wb").write(raw)
            out.append(dst)
        elif kind == "GZIP":
            raw = _gz.decompress(data)
            name = os.path.basename(path)
            for suf in (".gz", ".tgz"):
                if name.lower().endswith(suf):
                    name = name[: -len(suf)]
                    break
            dst = os.path.join(base, name or "unpacked.bin")
            open(dst, "wb").write(raw)
            out.append(dst)
        elif kind == "ZSTD":
            try:
                import zstandard
                raw = zstandard.ZstdDecompressor().decompress(data, max_output_size=1 << 28)
            except Exception:
                try:
                    from compression import zstd as _zstd  # Python 3.14+
                    raw = _zstd.decompress(data)
                except Exception:
                    return out
            dst = os.path.join(base, os.path.basename(path) + ".out")
            open(dst, "wb").write(raw)
            out.append(dst)
        elif kind == "TAR":
            with tarfile.open(fileobj=__import__("io").BytesIO(data)) as tf:
                for m in tf.getmembers()[:40]:
                    if not m.isfile() or m.name.startswith("/") or ".." in m.name:
                        continue
                    dst = os.path.join(base, os.path.basename(m.name))
                    with open(dst, "wb") as f:
                        f.write(tf.extractfile(m).read())
                    out.append(dst)
        elif kind == "ZIP":
            with zipfile.ZipFile(path) as z:
                for nm in z.namelist()[:40]:
                    if nm.endswith("/") or ".." in nm:
                        continue
                    dst = os.path.join(base, os.path.basename(nm))
                    with open(dst, "wb") as f:
                        f.write(z.read(nm))
                    out.append(dst)
    except Exception:
        return out
    return out


def near_dup_text(path, sample=200_000):
    """Много строк и мало уникальных? Значит, задача «одна строка отличается»."""
    try:
        with open(path, "rb") as f:
            raw = f.read(sample)
    except OSError:
        return False
    if raw.count(b"\n") < 200:
        return False
    lines = raw.decode("utf-8", "replace").splitlines()
    if len(lines) < 200:
        return False
    return len(set(lines)) / len(lines) < 0.05


def sibling_texts(path, limit=3):
    """Короткие печатные файлы рядом — вход для BF/Ook и подобного."""
    out = []
    d = os.path.dirname(path) or "."
    try:
        names = sorted(os.listdir(d))
    except OSError:
        return out
    for name in names:
        p2 = os.path.join(d, name)
        if p2 == path or not os.path.isfile(p2):
            continue
        try:
            if os.path.getsize(p2) > 4096 or os.path.getsize(p2) == 0:
                continue
            data = open(p2, "rb").read()
        except OSError:
            continue
        if not data or common.printable_ratio(data) < 0.95:
            continue
        try:
            text = data.decode("utf-8").strip()
        except UnicodeDecodeError:
            continue
        if not text or len(text) > 512:
            continue
        out.append((name, text))
        if len(out) >= limit:
            break
    return out


def steps_for(path, deep=False, depth=0):
    """[(имя_инструмента, аргументы, зачем, таймаут)] по типу данных."""
    data = common.read_bytes(path)[:2_000_000] if os.path.isfile(path) else b""
    kind = common.sniff(data[:4096]) if data else "unknown"
    ext = os.path.splitext(path)[1].lower()
    steps = []
    add = steps.append

    if os.path.isdir(path):
        add(("hunt", [path], "строки/секреты во всех файлах", 60))
        add(("flaghunt", [path], "файлы flag/flag.txt/user.txt", 60))
        return steps, "DIR"

    # Архивы: flag.wav.xz, traffic.pcapng.xz, dump.tar.bz2. Распаковываем
    # и строим план уже для внутреннего файла — иначе solve видит «unknown».
    akind = _archive_kind(path, data) if data else None
    if akind in ("XZ", "BZ2", "GZIP", "ZSTD", "LZ4", "TAR") and depth < 2:
        inner_files = unpack_one(path)
        for inner in inner_files[:6]:
            sub, _subkind = steps_for(inner, deep, depth + 1)
            tag = f"{os.path.basename(path)} → {os.path.basename(inner)}"
            for n2, a2, w2, t2 in sub[:12]:
                add((n2, a2, f"{tag}: {w2}", t2))

    # архивы и офисные документы
    emb = toolbox._scan_embedded(data) if data else {}
    zip_like = data[:4] == b"PK\x03\x04" or ext in (
        ".zip", ".docx", ".xlsx", ".pptx", ".jar", ".apk", ".ipa",
        ".odp", ".ods", ".odt", ".epub")
    if "ZIP" in emb and data[:4] != b"PK\x03\x04":
        add(("carve", [path, "--out", carve_dir(path)], "ZIP лежит внутри файла", 40))
        zip_like = True
    if zip_like:
        add(("zipmeta", [path, "--decode"], "комментарии/имена/лишние поля", 30))
        if ext in (".docx", ".xlsx", ".pptx"):
            dump = os.path.join(tempfile.gettempdir(), "solve_doc",
                                os.path.basename(path) + ".txt")
            xml_dump = os.path.join(tempfile.gettempdir(), "solve_doc",
                                    os.path.basename(path) + ".document.xml")
            add(("text", [path, "--out", dump], "текст документа", 30))
            add(("ws", [dump], "пробелы/zero-width в тексте документа", 30))
            for xp in prep_docx(path)[:3]:
                add(("ws", [xp], "пробелы/zero-width в XML документа", 30))
            runs_dump = prep_docx_runs(path)
            if runs_dump:
                add(("ws", [runs_dump, "--mode", "trail"],
                     "хвостовые пробелы/табы в runs документа", 30))
            add(("ooxml", [path], "структура OOXML/скрытые части", 40))
        if ext == ".apk":
            add(("apk", [path], "манифест/секреты APK", 40))
        if ext == ".ipa":
            add(("ipa", [path], "Info.plist/строки IPA", 40))

    if kind == "PNG":
        add(("png_chunks", [path], "нестандартные чанки/текст", 30))
        add(("lsb", [path], "младшие биты", 40))
        add(("zsteg", [path], "перебор LSB-раскладок", 40))
        add(("alpha", [path], "альфа-канал", 40))
        add(("qr", [path], "QR на картинке", 30))
        add(("ocr", [path], "текст с картинки", 40))
        add(("ocr", [path, "--variants"], "текст + правки ошибок OCR", 50))
        add(("geo", [path], "EXIF/GPS + ссылки для поиска", 30))
        if deep:
            add(("lsb", [path, "--channel", "all"], "все каналы", 60))
            add(("lsb", [path, "--order", "msb"], "старшие биты", 60))
            add(("lsb", [path, "--bits", "2"], "два бита", 60))
            add(("runs", [path], "длинные однотипные участки", 40))
    elif kind == "JPEG":
        add(("jpeg_tail", [path], "данные после EOI", 30))
        add(("exif", [path], "EXIF/комментарии", 30))
        add(("lsb", [path], "младшие биты", 40))
        add(("ocr", [path], "текст с картинки", 40))
        add(("ocr", [path, "--variants"], "текст + правки ошибок OCR", 50))
        add(("geo", [path], "EXIF/GPS + ссылки для поиска", 30))
    elif kind == "GIF":
        add(("gif_frames", [path], "кадры/палитра", 30))
        add(("video", [path, "--every", "1", "--max", "80"],
             "кадры + OCR", 90))

    if kind in ("MP4", "AVI", "MKV", "MOV", "WEBM") or ext in (
            ".mp4", ".mkv", ".avi", ".mov", ".webm"):
        add(("exif", [path], "метаданные контейнера", 30))
        add(("hunt", [path], "строки в контейнере", 40))
        add(("video", [path, "--every", "10", "--max", "80"],
             "кадры + OCR", 120))

    if kind == "RIFF" or ext in (".wav",):
        add(("audiotools", [path, "--raw"], "морзе/DTMF", 40))
        if deep:
            add(("audio", [path], "спектрограмма", 60))
    elif kind in ("MP3", "OGG"):
        add(("audio", [path], "спектрограмма", 60))
        add(("audiotools", [path, "--raw"], "морзе/DTMF", 40))

    # ключ/IV могут лежать в соседней подсказке (hint.txt)
    hint = hint_params(path)
    if hint.get("key") and data and len(data) % 16 == 0 and len(data) >= 32:
        add(("ecb", [path, "--key", hint["key"], "--decrypt"], "рядом ключ — проверить ECB", 30))
        if hint.get("iv"):
            add(("aes", [path, "--key", hint["key"], "--iv", hint["iv"]],
                 "рядом ключ и IV — AES-CBC", 40))

    if kind in ("PCAP", "PCAPNG"):
        add(("dns", [path], "канал в DNS", 60))
        add(("creds", [path], "пароли/куки", 40))
        add(("http", [path], "тела HTTP", 40))
        add(("icmp", [path], "ICMP payload/скрытый канал", 40))
        # рядом может лежать лог с секретом/ключом (например Minecraft)
        try:
            ddir = os.path.dirname(path) or "."
            logs = [os.path.join(ddir, n) for n in sorted(os.listdir(ddir))
                    if n.lower().endswith((".log", ".txt"))][:3]
        except OSError:
            logs = []
        for lg in logs:
            add(("mc", [path, "--log", lg], f"Minecraft: секрет из {os.path.basename(lg)}", 60))
        if deep:
            add(("udp", [path], "полезная нагрузка UDP", 40))
            add(("reasm", [path], "склейка TCP-потоков", 60))
            add(("mc", [path], "Minecraft-протокол", 60))

    # PEM/DER-ключ: рядом часто лежит cipher.bin/flag.enc
    if ext in (".pem", ".pub", ".key", ".crt", ".der") or b"-----BEGIN" in data[:200]:
        sib = None
        try:
            d = os.path.dirname(path) or "."
            for nm in sorted(os.listdir(d)):
                p2 = os.path.join(d, nm)
                if p2 == path or not os.path.isfile(p2):
                    continue
                if os.path.getsize(p2) > 1_000_000:
                    continue
                if re.search(r"(cipher|flag|enc|secret|msg|data)", nm, re.I):
                    sib = p2
                    break
        except OSError:
            sib = None
        rsa_args = ["auto", path] + (["--cipher", sib] if sib else [])
        add(("rsa", rsa_args, "PEM/DER-ключ: n/e/d и атаки", 60))

    if kind in ("ELF", "PE"):
        add(("strings", [path], "строки с ключевыми словами", 40))
        add(("disasm", [path, "--interesting", "--limit", "400"],
             "дизасм: сравнения, константы, ссылки на строки", 60))
        add(("megarev", [path, "--no-crypto", "--time", "30"], "строки/PIN/вложенные/ключи", 60))
        if deep:
            add(("megarev", [path, "--deep", "--time", "60"], "глубокий разбор бинарника", 90))
            add(("ghidra", [path, "--out", os.path.join(tempfile.gettempdir(), "solve_ghidra",
                                                        os.path.basename(path) + ".c"),
                            "--timeout", "180"],
                 "декомпиляция в C (Ghidra headless)", 200))

    if kind == "PDF":
        add(("text", [path], "текст/вложения", 30))
        add(("hunt", [path], "строки и секреты", 40))

    if kind == "SQLite" or ext in (".db", ".sqlite"):
        add(("android", [path], "таблицы/чаты/токены", 40))
        add(("hunt", [path], "строки из базы", 40))

    if kind in ("GZIP", "7Z", "RAR", "TAR"):
        add(("carve", [path, "--out", os.path.join(tempfile.gettempdir(), "solve_carve")],
             "вырезать вложения", 40))

    # текст
    if kind == "unknown" and data:
        text = read_text(path)
        if len(data) <= 65536 and len(data) >= 5:
            pre = (common.prefixes() or ["CTF"])[0]
            add(("xorknown", [path, "--known", f"{pre}{{"],
                 "XOR: текст начинается с префикса флага", 20))
        if text and common.printable_ratio(text) >= 0.85:
            try:
                doc0 = json.loads(text)
            except Exception:
                doc0 = None
            if isinstance(doc0, dict) and (doc0.get("certificates") or doc0.get("keys")):
                tgt0 = str(doc0.get("target") or "")
                e0 = doc0.get("public_exponent") or doc0.get("e") or 65537
                cf0 = "wrapped_session_key" if doc0.get("wrapped_session_key") else "wrapped"
                add(("rsa", ["shared", "--json", path, "--target", tgt0,
                             "--e", str(e0), "--cipher-field", cf0],
                     "JSON-реестр модулей: общий множитель + ключ сессии", 60))
            add(("ws", [path], "пробелы/zero-width", 30))
            if near_dup_text(path):
                add(("nearlines", [path], "почти одинаковые строки: отличия", 40))
            # EVM calldata: 0x + селектор + слова по 32 байта
            if re.fullmatch(r"(?i)0x[0-9a-f]{16,}", (text or "").strip()):
                add(("evm", [path], "EVM calldata: селектор и аргументы", 20))
            # pickle-модель: протокол 0+ начинается с 0x80
            if (ext in (".pkl", ".pickle", ".pt", ".pth", ".joblib")
                    or (data[:1] == b"\x80")):
                add(("pickle", [path], "pickle: опасные глобалы и строки", 40))
            add(("esolang", [path], "BF/Ook/Cow/Befunge/Whitespace", 40))
            # BF/Ook часто читает строку-вход, которая лежит рядом
            for _nm, _inp in sibling_texts(path):
                add(("esolang", [path, "--input", _inp],
                     f"эзотерика с входом из {_nm}", 40))
            add(("enc", ["--file", path], "кодировки строкой", 20))
            add(("autocrack", ["--file", path], "цезарь/XOR/кодировки/хеши", 60))
            if len(re.findall(r"[A-Za-zА-Яа-я]", text)) >= 200:
                add(("classical", ["vigenere-crack", "--text", text[:6000]],
                     "длинный текст без пробелов — Виженер/Цезарь", 40))
            if len(re.findall(r"\d{10,}", text)) >= 2:
                add(("rsa", ["auto", path], "RSA: числа из текста, все атаки", 60))
                add(("all", [path, "--time", "25"], "остальные шифры/хеши", 45))
            hashes = list(dict.fromkeys(re.findall(r"\b[0-9a-fA-F]{32}\b|\b[0-9a-fA-F]{40}\b|"
                                                   r"\b[0-9a-fA-F]{64}\b", text)))[:3]
            local_wl = None
            d_dir = os.path.dirname(path) or "."
            try:
                for nm in sorted(os.listdir(d_dir))[:200]:
                    if re.search(r"(word|pass|cand).*\.(txt|lst)$", nm, re.I):
                        local_wl = os.path.join(d_dir, nm)
                        break
            except OSError:
                pass
            wl = local_wl or find_wordlist()
            for h in hashes:
                add(("autocrack", ["--hash", h], "похоже на хеш: тип + словарь", 60))
                if wl:
                    add(("hashcat", [h, "--wordlist", wl], "хеш + словарь (hashcat/GPU)", 120))
            try:
                doc = json.loads(text)
            except Exception:
                doc = None
            if isinstance(doc, dict) and (doc.get("certificates") or doc.get("keys")):
                tgt = str(doc.get("target") or "")
                e_v = doc.get("public_exponent") or doc.get("e") or 65537
                cf = "wrapped_session_key" if doc.get("wrapped_session_key") else "wrapped"
                args_rsa = ["shared", "--json", path, "--target", tgt,
                            "--e", str(e_v), "--cipher-field", cf]
                add(("rsa", args_rsa, "JSON-реестр модулей: общий множитель + ключ сессии", 60))
            jwtm = re.search(r"eyJ[\w-]{5,}\.[\w-]{5,}\.[\w-]*", text)
            if jwtm:
                add(("jwt", ["decode", jwtm.group(0)], "JWT в тексте", 20))
            if deep:
                add(("obscure", ["auto", "--text", text[:6000]], "base58/Bacon/ADFGX/Hill/…", 40))
                add(("autocrack", ["--file", path, "--deep"], "глубокий перебор", 90))
        elif len(data) <= 8192 and common.printable_ratio(data) < 0.8:
            # короткий бинарный блоб: самый частый случай — XOR с префиксом флага
            pre = (common.prefixes() or ["CTF"])[0]
            add(("xorknown", [path, "--known", f"{pre}{{"],
                 "XOR: текст начинается с префикса флага", 20))
            add(("autocrack", ["--file", path], "XOR/кодировки/хеши", 60))
            add(("enc", ["--file", path], "все кодировки/base (utf-16/32, cp, baseN)", 30))

    # что осталось — универсальные переборы
    if ext in (".pkl", ".pickle", ".pt", ".pth", ".joblib") or data[:1] == b"\x80":
        add(("pickle", [path], "pickle: опасные глобалы и строки", 40))
    add(("hunt", [path], "секреты и флаги в строках", 40))
    add(("carve", [path, "--out", carve_dir(path)], "файлы внутри файла", 40))
    if deep:
        add(("all", [path, "--time", "40"], "шифры/кодировки/ключи", 60))
    seen = set()
    uniq_steps = []
    for step in steps:
        key = (step[0], tuple(map(str, step[1])))
        if key in seen:
            continue
        seen.add(key)
        uniq_steps.append(step)
    return uniq_steps, kind


def solve_file(target, runner, deep, plan_only):
    steps, kind = steps_for(target, deep)
    print(f"[+] тип: {kind}")
    if plan_only:
        for i, (name, args, why, timeout) in enumerate(steps, 1):
            print(f"  {i:02d}. {name} {' '.join(map(str, args))}   # {why}")
        if os.path.isdir(target):
            for p, k in toolbox._pick_files(target)[:6]:
                print(f"  +  {k:8s} {p}")
        return None
    flag = runner.run_many(steps)
    if flag:
        return flag
    # после carve: разобрать вырезанные файлы. Режем и сам target, и то,
    # что распаковалось из архива (wav.xz → wav → pcapng внутри).
    carve_sources = [target]
    if os.path.isfile(target):
        try:
            carve_sources += unpack_one(target)[:4]
        except Exception:
            pass
    for src in carve_sources:
        outdir = carve_dir(src)
        if not os.path.isdir(outdir):
            continue
        inner = sorted(f for f in os.listdir(outdir)
                       if os.path.isfile(os.path.join(outdir, f)))
        if inner:
            print(f"[i] внутри {os.path.basename(src)} нашлось {len(inner)} шт., "
                  f"прогоняю по ним")
            for f in inner[:5]:
                p2 = os.path.join(outdir, f)
                # не жёсткий список, а план по типу внутреннего файла:
                # pcap → http/creds, wav → morse/DTMF, zip → метаданные и т.д.
                sub_steps, _subk = steps_for(p2)
                for n2, a2, w2, t2 in sub_steps[:8]:
                    if n2 == "carve":
                        continue
                    flag = runner.run(n2, a2,
                                      f"{os.path.basename(p2)}: {w2}", t2)
                    if flag:
                        return flag
    # цепочка: вывод инструментов часто сам является закодированной строкой
    cands = harvest_candidates(runner)
    if cands:
        print(f"[i] цепочка: {len(cands)} кандидатов из вывода, пробую декодировать")
        for c in cands:
            if time.time() >= runner.deadline - 1:
                print("[i] бюджет кончился на цепочке")
                break
            flag = runner.run("enc", [c], "декод кандидата из вывода", 15)
            if flag:
                return flag

    if os.path.isdir(target):
        picked = toolbox._pick_files(target)
        if picked:
            print(f"[i] в папке {len(picked)} интересных файлов, разбираю "
                  f"{'параллельно' if runner.jobs > 1 else 'по одному'}")
        if runner.jobs > 1 and len(picked) > 1:
            def _child(item):
                p, k = item
                if time.time() >= runner.deadline - 2 or runner.stop.is_set():
                    return None
                sub, _ = steps_for(p, deep=deep)
                seq = [(n2, a2, f"{os.path.basename(p)}: {w2}", t2)
                       for n2, a2, w2, t2 in sub[:6] if n2 != "carve"]
                return runner.run_serial(seq)

            with ThreadPoolExecutor(max_workers=runner.jobs) as ex:
                futs = [ex.submit(_child, item) for item in picked]
                for fut in as_completed(futs):
                    flag = fut.result()
                    if flag:
                        runner.stop.set()
                        for f2 in futs:
                            f2.cancel()
                        return flag
        else:
            for p, k in picked:
                if time.time() >= runner.deadline - 2:
                    print("[i] бюджет кончился, остальные файлы пропускаю")
                    break
                print(f"--- {k}: {os.path.basename(p)}")
                sub_steps, _ = steps_for(p, deep=deep)
                for n2, a2, w2, t2 in sub_steps[:6]:
                    if n2 == "carve":
                        continue
                    flag = runner.run(n2, a2, f"{os.path.basename(p)}: {w2}", t2)
                    if flag:
                        return flag
    return None


def solve_url(url, runner, deep):
    flag = runner.run("recon", [url], "ссылки/формы/JS/куки/robots/флаги", 40)
    if flag:
        return flag
    flag = runner.run("param", [url] + (["--methods", "GET,POST"] if deep else []),
                      "SQLi/XSS/траверсал + поиск флага в ответе", 60)
    if flag:
        return flag
    if deep:
        return runner.run("dirfuzz", [url], "скрытые пути", 90)
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("target", help="файл, папка, строка, URL или host:port")
    ap.add_argument("--time", type=float, default=90, help="общий бюджет, сек")
    ap.add_argument("--jobs", type=int, default=4, help="сколько шагов считать параллельно")
    ap.add_argument("--deep", action="store_true", help="включить дорогие шаги")
    ap.add_argument("--verbose", action="store_true", help="печатать вывод каждого шага")
    ap.add_argument("--plan", action="store_true", help="только показать план")
    ap.add_argument("--log", help="сохранить полный вывод шагов")
    common.add_flag_args(ap)
    args = ap.parse_args()
    common.apply_flag_args(args)
    if args.any_prefix:
        os.environ["FLAG_ANY"] = "1"

    target = args.target
    runner = Runner(args.time, args.verbose, args.log, args.jobs)

    if os.path.exists(target):
        flag = solve_file(target, runner, args.deep, args.plan)
    elif target.lower().startswith(("http://", "https://")):
        print("[+] цель: URL")
        flag = solve_url(target, runner, args.deep)
    elif ":" in target and target.rsplit(":", 1)[1].isdigit():
        print("[+] цель: сервис host:port — автопилот не угадывает протокол")
        print("    сначала посмотри, что он говорит:")
        print(f"    python toolbox.py oracle --connect {target} --peek")
        print("    потом опиши вопрос формулой:")
        print(f"    python toolbox.py oracle --connect {target} --match \"(\\d+)\" --expr \"v\"")
        print("    если это эхо/format string:")
        print(f"    python toolbox.py fmtstr scan --connect {target} --deref")
        return
    else:
        print("[+] цель: строка")
        flag = None
        for name, sargs, why, timeout in (
            ("enc", [target], "кодировки во все стороны", 20),
            ("autocrack", ["--text", target], "шифры/кодировки", 40),
            ("obscure", ["auto", "--text", target], "экзотические кодировки", 30),
        ):
            flag = runner.run(name, sargs, why, timeout)
            if flag:
                break
        if not flag:
            print("    ещё: python toolbox.py auto <строка>")

    if not flag:
        print("\n[-] флаг не найден за отведённое время.")
        if runner.grabs:
            print("[i] зацепки (не флаг, но полезно):")
            for g in dict.fromkeys(runner.grabs):
                print("   ", g)
        print("    что можно ещё: --deep, больше --time, или конкретный инструмент из плана")
    runner.dump_log()


if __name__ == "__main__":
    main()
