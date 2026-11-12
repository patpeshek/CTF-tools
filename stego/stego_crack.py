#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
stego_crack.py — перебор паролей для стего-контейнеров через внешние тулзы.

Гоняет steghide / outguess / stegseek (и подсказывает команду для F5 и
stegdetect) с паролями из условия задачи и словаря, ищет флаг в извлечённом.

  python stego_crack.py secret.jpg
  python stego_crack.py secret.wav --password hunter2 --password letmein
  python stego_crack.py secret.jpg --desc "пароль: s3cr3t"
  python stego_crack.py secret.jpg --wordlist rockyou.txt --max 20000

Каждый внешний инструмент НЕОБЯЗАТЕЛЕН: если его нет в PATH, печатается
подсказка и готовая команда, и работа продолжается — без трейсбека.

Пароли берутся из: --password (можно несколько), --wordlist FILE,
--desc/--desc-file (текст условия), соседних текстовых файлов рядом с
контейнером, плюс небольшой встроенный список (пустой пароль, имя файла и
типовые CTF-пароли).
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
import os
import re
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import common  # noqa: E402

BUILTIN = [
    "", "password", "123456", "12345678", "admin", "secret", "changeme",
    "letmein", "qwerty", "flag", "ctf", "steghide", "stego", "hidden",
    "P@ssw0rd", "iloveyou", "root", "toor", "123456789",
]

# текстовые соседи, которые обычно содержат условие/пароль
SIBLING_PATTERNS = ("hint", "readme", "read_me", "desc", "task", "note",
                    "password", "pass", "key", "flag")
SIBLING_EXT = (".txt", ".md", ".nfo", ".rst", "")

# кавычки всех мастей: 'x', "x", `x`, «x», “x”, ‘x’
_QUOTE_PAIRS = [("\"", "\""), ("'", "'"), ("`", "`"),
                ("«", "»"), ("“", "”"), ("‘", "’")]
_KW_RE = re.compile(
    r"(?i)(?:passphrase|password|passwd|pass|secret|пароль|кодовое\s+слово|"
    r"кодовая\s+фраза|ключ|key)\s*"
    r"(?:is|was|это|равен|равна|—|-|–|:|=)?\s*"
    r"[\"'`«“‘]?([^\s\"'`»”’\n]{2,64})")


def extract_passwords(text: str) -> list[str]:
    """Пароли из текста условия: в кавычках + после слова «пароль/password»."""
    out: list[str] = []
    if not text:
        return out
    for open_q, close_q in _QUOTE_PAIRS:
        pat = re.escape(open_q) + r"([^" + re.escape(close_q) + r"\n]{1,64})" + re.escape(close_q)
        for m in re.finditer(pat, text):
            out.append(m.group(1))
    for m in _KW_RE.finditer(text):
        out.append(m.group(1))
    cleaned = []
    for tok in out:
        tok = tok.strip().strip(".,;:!?)(][}{«»")
        if tok and tok not in cleaned:
            cleaned.append(tok)
    return cleaned


def sibling_passwords(carrier: str, cap: int = 50) -> list[str]:
    """Проходит по небольшим текстовым файлам рядом и достаёт пароли из них."""
    out: list[str] = []
    try:
        folder = os.path.dirname(os.path.abspath(carrier)) or "."
        names = sorted(os.listdir(folder))
    except OSError:
        return out
    base = os.path.basename(carrier).lower()
    count = 0
    for name in names:
        p = os.path.join(folder, name)
        if os.path.abspath(p) == os.path.abspath(carrier) or not os.path.isfile(p):
            continue
        low = name.lower()
        if low == base:
            continue
        ext = os.path.splitext(low)[1]
        stem = os.path.splitext(low)[0]
        looks = ext in SIBLING_EXT and (
            any(k in stem for k in SIBLING_PATTERNS) or ext in (".txt", ".md", ".nfo"))
        if not looks:
            continue
        try:
            if os.path.getsize(p) > 64 * 1024:
                continue
            text = open(p, "rb").read().decode("utf-8", "replace")
        except OSError:
            continue
        for pw in extract_passwords(text):
            if pw not in out:
                out.append(pw)
        count += 1
        if count >= 5 or len(out) >= cap:
            break
    return out[:cap]


def load_wordlist(path: str, cap: int) -> tuple[list[str], bool]:
    """Словарь с ограничением по размеру; возвращает (слова, усечён ли)."""
    words: list[str] = []
    truncated = False
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                w = line.rstrip("\r\n")
                if not w:
                    continue
                words.append(w)
                if len(words) >= cap:
                    truncated = True
                    break
    except OSError as e:
        print(f"[-] словарь не прочитан: {getattr(e, 'filename', None) or e}")
    return words, truncated


def assemble_passwords(args) -> tuple[list[str], bool]:
    """Собрать и упорядочить пароли: сначала явные, потом условие/встроенные/словарь."""
    stem = os.path.splitext(os.path.basename(args.carrier))[0]
    ordered: list[str] = []

    def add(seq):
        for pw in seq:
            if pw is None:
                continue
            if pw not in ordered:
                ordered.append(pw)

    add(args.password or [])
    add([""])  # пустой пароль — очень частый случай для steghide
    desc_text = args.desc or ""
    if args.desc_file:
        try:
            desc_text += "\n" + open(args.desc_file, "rb").read().decode("utf-8", "replace")
        except OSError as e:
            print(f"[-] --desc-file не прочитан: {getattr(e, 'filename', None) or e}")
    add(extract_passwords(desc_text))
    if not args.no_sibling:
        add(sibling_passwords(args.carrier))
    add([stem])
    add(BUILTIN)

    truncated = False
    if args.wordlist:
        words, truncated = load_wordlist(args.wordlist, args.max)
        if truncated:
            print(f"[!] словарь усечён до {args.max} строк (--max), "
                  f"остальное пропущено")
        add(words)
    return ordered, truncated


def find_bin(name: str, override: str | None) -> str | None:
    """Путь к внешнему инструменту: явный --*-bin или поиск в PATH."""
    if override:
        return override if os.path.exists(override) else shutil.which(override)
    return shutil.which(name)


def _scan(data: bytes, tool: str, pw: str) -> list[str]:
    flags = common.find_flags(data)
    if flags:
        shown = pw if pw else "<пусто>"
        print(f"[+] {tool}: пароль «{shown}» подошёл, извлечено {len(data)} байт")
        for fl in dict.fromkeys(flags):
            print(f"[+] ФЛАГ: {fl}  (tool={tool}, password={pw!r})")
    return flags


def try_steghide(binpath: str, carrier: str, pw: str, outdir: str) -> bytes | None:
    out = os.path.join(outdir, "steghide_out.bin")
    try:
        if os.path.exists(out):
            os.remove(out)
    except OSError:
        pass
    cmd = [binpath, "extract", "-sf", carrier, "-p", pw, "-xf", out, "-f"]
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=20)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if r.returncode == 0 and os.path.exists(out) and os.path.getsize(out) > 0:
        try:
            return open(out, "rb").read()
        except OSError:
            return None
    return None


def try_outguess(binpath: str, carrier: str, pw: str, outdir: str) -> bytes | None:
    out = os.path.join(outdir, "outguess_out.bin")
    try:
        if os.path.exists(out):
            os.remove(out)
    except OSError:
        pass
    cmd = [binpath, "-k", pw, "-r", carrier, out]
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=20)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if os.path.exists(out) and os.path.getsize(out) > 0:
        try:
            return open(out, "rb").read()
        except OSError:
            return None
    return None


def run_stegseek(binpath: str, carrier: str, passwords: list[str], outdir: str) -> bytes | None:
    """stegseek — быстрый перебор steghide; кормим ему собранный словарь."""
    wl = os.path.join(outdir, "stegseek_wl.txt")
    out = os.path.join(outdir, "stegseek_out.bin")
    try:
        with open(wl, "w", encoding="utf-8", errors="replace") as f:
            for pw in passwords:
                f.write(pw + "\n")
    except OSError:
        return None
    cmd = [binpath, carrier, wl, out, "-f", "-q"]
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=120)
    except (OSError, subprocess.TimeoutExpired):
        return None
    txt = (r.stdout + r.stderr).decode("utf-8", "replace")
    for line in txt.splitlines():
        if "passphrase" in line.lower():
            print("[+] stegseek:", line.strip())
    if os.path.exists(out) and os.path.getsize(out) > 0:
        try:
            return open(out, "rb").read()
        except OSError:
            return None
    return None


def print_missing_hint(carrier: str, missing: list[str], f5_jar: str | None):
    print("[i] Внешние стего-инструменты не найдены в PATH:",
          ", ".join(missing))
    print("[i] Установи нужный и запусти команду вручную:")
    if "steghide" in missing:
        print(f"[i]   steghide:   steghide extract -sf {carrier} -p <password>")
    if "outguess" in missing:
        print(f"[i]   outguess:   outguess -k <password> -r {carrier} out.bin")
    if "stegseek" in missing:
        print(f"[i]   stegseek:   stegseek {carrier} <wordlist>   "
              f"(быстрый перебор steghide)")


def f5_and_stegdetect(carrier: str, passwords: list[str], f5_jar: str | None):
    """F5 (java) и stegdetect: не тащим JVM, только печатаем команду, если есть."""
    java = shutil.which("java")
    stegdetect = shutil.which("stegdetect")
    jar = f5_jar
    if not jar:
        for cand in ("f5.jar", "F5.jar", "Extract.jar"):
            w = shutil.which(cand)
            if w:
                jar = w
                break
    if java and jar:
        print("[i] F5 доступен (java + jar) — ручной перебор, напр.:")
        for pw in passwords[:5]:
            shown = pw if pw else '""'
            print(f"[i]   java -jar {jar} x -p {shown} -e out.bin {carrier}")
    elif java:
        print("[i] java есть, но jar F5 не найден — укажи --f5-jar <path> и запусти:")
        print(f"[i]   java -jar <f5.jar> x -p <password> -e out.bin {carrier}")
    if stegdetect:
        print(f"[i] stegdetect есть — проверить наличие стего: stegdetect -tjopi {carrier}")


def main():
    ap = argparse.ArgumentParser(description="перебор паролей стего-контейнера")
    ap.add_argument("carrier", help="файл-контейнер (JPEG/BMP/WAV/PNG)")
    ap.add_argument("--password", action="append", default=[],
                    help="пароль (можно несколько раз)")
    ap.add_argument("--wordlist", help="файл словаря (перебор только при явном указании)")
    ap.add_argument("--desc", help="текст условия: вытащить пароли из кавычек/после «пароль:»")
    ap.add_argument("--desc-file", help="файл с текстом условия")
    ap.add_argument("--max", type=int, default=5000,
                    help="предел строк словаря (по умолчанию 5000)")
    ap.add_argument("--no-sibling", action="store_true",
                    help="не искать пароли в соседних текстовых файлах")
    ap.add_argument("--steghide-bin", help="путь к steghide (иначе из PATH)")
    ap.add_argument("--outguess-bin", help="путь к outguess (иначе из PATH)")
    ap.add_argument("--stegseek-bin", help="путь к stegseek (иначе из PATH)")
    ap.add_argument("--f5-jar", help="путь к jar-реализации F5")
    common.add_flag_args(ap)

    # допускаем ведущее слово-подкоманду: auto / crack
    argv = sys.argv[1:]
    if argv and argv[0] in ("auto", "crack"):
        argv = argv[1:]
    args = ap.parse_args(argv)
    common.apply_flag_args(args)

    if not os.path.exists(args.carrier):
        print(f"[-] не могу открыть: {args.carrier}")
        return
    if os.path.isdir(args.carrier):
        print(f"[-] это папка, а не файл: {args.carrier}")
        return

    try:
        kind = common.sniff(open(args.carrier, "rb").read(4096))
    except OSError as e:
        print(f"[-] не могу открыть: {getattr(e, 'filename', None) or e}")
        return
    print(f"[+] контейнер: {args.carrier} ({kind})")

    passwords, _ = assemble_passwords(args)
    print(f"[+] паролей к перебору: {len(passwords)}")

    steghide = find_bin("steghide", args.steghide_bin)
    outguess = find_bin("outguess", args.outguess_bin)
    stegseek = find_bin("stegseek", args.stegseek_bin)

    present = []
    missing = []
    for nm, pth in (("steghide", steghide), ("outguess", outguess),
                    ("stegseek", stegseek)):
        (present if pth else missing).append(nm)
    if present:
        print("[+] найдены инструменты:", ", ".join(present))
    if missing:
        print_missing_hint(args.carrier, missing, args.f5_jar)

    outdir = tempfile.mkdtemp(prefix="stegopass_")
    found = False
    try:
        if stegseek:
            data = run_stegseek(stegseek, args.carrier, passwords, outdir)
            if data and _scan(data, "stegseek", "<словарь>"):
                found = True

        if not found and (steghide or outguess):
            for pw in passwords:
                if steghide:
                    data = try_steghide(steghide, args.carrier, pw, outdir)
                    if data:
                        if _scan(data, "steghide", pw):
                            found = True
                            break
                        print(f"[i] steghide извлёк {len(data)} байт на пароле "
                              f"{pw!r}, но флага нет — проверь вручную")
                if outguess:
                    data = try_outguess(outguess, args.carrier, pw, outdir)
                    if data and _scan(data, "outguess", pw):
                        found = True
                        break
    finally:
        shutil.rmtree(outdir, ignore_errors=True)

    if not found:
        f5_and_stegdetect(args.carrier, passwords, args.f5_jar)
        if not present:
            print("[i] готовых инструментов нет — выполнить команды выше вручную")
        else:
            print("[-] флаг не найден перебором; попробуй словарь побольше "
                  "(--wordlist) или другой инструмент")


if __name__ == "__main__":
    try:
        main()
    except (FileNotFoundError, IsADirectoryError, PermissionError) as e:
        print(f"[-] не могу открыть: {getattr(e, 'filename', None) or e}")
    except BrokenPipeError:
        pass
    except KeyboardInterrupt:
        print("\n[-] прервано")
