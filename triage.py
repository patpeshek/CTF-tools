#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
triage.py — первый прогон по файлу или папке.

Что делает:
  * определяет реальный тип файлов по magic-байтам (а не по расширению);
  * ищет флаги (CTF{...}, ctf{...}, flag{...});
  * ищет base64/hex-кандидаты, URL, подозрительные строки;
  * для картинок печатает размер/режим, для zip/docx — список файлов и комментарии;
  * складывает всё в отчёт, ничего не меняет на диске.

Использование:
  python triage.py <файл_или_папка> [--max-strings 40] [--out report.txt]
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
import os
import re
import sys
import zipfile

import common

B64_RE = re.compile(rb"[A-Za-z0-9+/]{16,}={0,2}")
HEX_RE = re.compile(rb"(?:0x)?[0-9a-fA-F]{24,}")
URL_RE = re.compile(rb"https?://[^\s\"'<>]{4,200}")

SIGS = [
    (b"\x89PNG\r\n\x1a\n", "PNG"),
    (b"\xff\xd8\xff", "JPEG"),
    (b"GIF87a", "GIF"),
    (b"GIF89a", "GIF"),
    (b"PK\x03\x04", "ZIP/DOCX/XLSX/APK"),
    (b"PK\x05\x06", "ZIP (empty)"),
    (b"\x1f\x8b", "GZIP"),
    (b"BZh", "BZIP2"),
    (b"\xfd7zXZ\x00", "XZ"),
    (b"7z\xbc\xaf\x27\x1c", "7Z"),
    (b"Rar!\x1a\x07", "RAR"),
    (b"%PDF", "PDF"),
    (b"\x7fELF", "ELF"),
    (b"MZ", "PE/EXE"),
    (b"SQLite format 3\x00", "SQLite"),
    (b"RIFF", "RIFF (WAV/AVI/WEBP)"),
    (b"ID3", "MP3 (ID3)"),
    (b"OggS", "OGG"),
    (b"\x00\x00\x01\x00", "ICO"),
    (b"LUKS\xba\xbe", "LUKS"),
    (b"\x53\xef", "ext2/3/4 superblock? (похоже)"),
    (b"ustar", "TAR"),
]

PRINTABLE = re.compile(rb"[\x20-\x7e]{6,}")


def sniff(path: str) -> str:
    with open(path, "rb") as f:
        head = f.read(512)
    for sig, name in SIGS:
        if head.startswith(sig) or (len(sig) > 2 and sig in head[:64]):
            return name
    return "unknown"


def strings_of(path: str, limit: int = 60):
    out = []
    with open(path, "rb") as f:
        data = f.read(8_000_000)  # хватит для учебных тасков
    for m in PRINTABLE.finditer(data):
        s = m.group()
        if len(s) >= 6:
            out.append(s)
        if len(out) >= limit:
            break
    return out


def b64_variants(blob: bytes):
    """Пытаемся декодировать строку как base64/hex/binary и вернуть осмысленное."""
    res = []
    try:
        pad = blob + b"=" * (-len(blob) % 4)
        dec = base64.b64decode(pad, validate=False)
        if dec and sum(32 <= c < 127 or c in b"\r\n\t" for c in dec) / len(dec) > 0.8:
            res.append(("base64", dec[:200]))
    except Exception:
        pass
    try:
        dec = binascii.unhexlify(blob)
        if dec and sum(32 <= c < 127 or c in b"\r\n\t" for c in dec) / len(dec) > 0.8:
            res.append(("hex", dec[:200]))
    except Exception:
        pass
    return res


def inspect(path: str, max_strings: int):
    lines = []
    try:
        size = os.path.getsize(path)
    except OSError as e:
        return [f"  ! не читается: {e}"]
    kind = sniff(path)
    lines.append(f"  тип: {kind}   размер: {size} байт")
    try:
        denial = common.api_denial_note(open(path, "rb").read(4096))
    except OSError:
        denial = None
    if denial:
        lines.append("  [!] " + denial)

    # картинки
    if kind in ("PNG", "JPEG", "GIF"):
        try:
            from PIL import Image
            im = Image.open(path)
            lines.append(f"  image: {im.format} {im.size} mode={im.mode} frames={getattr(im, 'n_frames', 1)}")
            exif = im.getexif()
            if exif:
                small = {k: v for k, v in list(exif.items())[:8]}
                lines.append(f"  exif: {small}")
        except Exception as e:
            lines.append(f"  image: не открылась ({e})")

    # архивы
    if kind.startswith("ZIP"):
        try:
            with zipfile.ZipFile(path) as z:
                infos = z.infolist()
                lines.append(f"  zip: {len(infos)} файлов, comment={z.comment!r}")
                for i in infos[:15]:
                    c = i.comment.decode("utf-8", "replace") if i.comment else ""
                    lines.append(f"    - {i.filename} ({i.file_size} b)" + (f"  COMMENT={c!r}" if c else ""))
                if len(infos) > 15:
                    lines.append(f"    ... ещё {len(infos) - 15}")
        except Exception as e:
            lines.append(f"  zip: ошибка ({e})")

    raw = open(path, "rb").read(8_000_000)
    flags = common.find_flags(raw)
    if flags:
        lines.append("  !!! ФЛАГИ: " + " | ".join(flags))

    ss = strings_of(path, max_strings)
    if ss:
        lines.append("  строки (первые):")
        for s in ss[:max_strings]:
            txt = s.decode("utf-8", "replace")
            lines.append("    " + txt[:160])

    # base64/hex кандидаты из строк
    cand = set()
    for s in ss:
        for m in B64_RE.finditer(s):
            cand.add(m.group())
        for m in HEX_RE.finditer(s):
            cand.add(m.group())
    shown = 0
    for c in list(cand)[:12]:
        for how, dec in b64_variants(c):
            lines.append(f"  {how} от {c[:40]!r} -> {dec!r}")
            shown += 1
    if shown == 0:
        # если строки не дали — пробуем сам файл целиком (маленький)
        if size < 20000:
            for how, dec in b64_variants(raw.strip()):
                lines.append(f"  {how} от файла -> {dec!r}")

    for m in URL_RE.finditer(raw):
        lines.append(f"  url: {m.group().decode('utf-8', 'replace')}")

    # что внутри документа/архива: текст и невидимые слои
    try:
        for label, text in common.document_text(path)[:6]:
            tags = common.classify_text(text)
            if not tags:
                continue
            lines.append(f"  [{label}] {len(text)} символов: {', '.join(tags)}")
            lines.append("    → " + tag_hint(tags))
    except Exception:
        pass
    return lines


def tag_hint(tags):
    hints = []
    if "whitespace-only" in tags:
        hints.append("python toolbox.py ws <файл> --mode ws")
    if any(t.startswith("zero-width") for t in tags):
        hints.append("python toolbox.py ws <файл> --mode zw")
    if any(t.startswith("variation") for t in tags):
        hints.append("python toolbox.py ws <файл> --mode vs")
    if any(t.startswith("braille") for t in tags):
        hints.append("python toolbox.py ws <файл> --mode braille")
    if "trailing-whitespace" in tags:
        hints.append("python toolbox.py ws <файл> --mode trail")
    if any(t.startswith("esolang") for t in tags):
        hints.append("python toolbox.py esolang <файл>")
    if "encoded-blob" in tags:
        hints.append("python toolbox.py auto <файл> / enc")
    return " ; ".join(hints) if hints else "-"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("path")
    ap.add_argument("--max-strings", type=int, default=30)
    ap.add_argument("--out")
    ap.add_argument("--json", action="store_true", help="машинный вывод")
    common.add_flag_args(ap)
    args = ap.parse_args()
    common.apply_flag_args(args)

    if not os.path.exists(args.path):
        print(f"[-] нет файла/папки: {args.path}")
        print("    проверь путь; список инструментов: python toolbox.py index")
        return

    targets = []
    if os.path.isdir(args.path):
        for root, _, files in os.walk(args.path):
            for f in files:
                targets.append(os.path.join(root, f))
    else:
        targets = [args.path]

    if args.json:
        import json as _json
        result = []
        for p in targets:
            try:
                data = open(p, "rb").read(8_000_000)
            except OSError:
                continue
            info = {
                "path": p,
                "size": os.path.getsize(p),
                "type": sniff(p),
                "flags": common.find_flags(data),
                "strings": [s.decode("utf-8", "replace") for s in strings_of(p, 20)],
                "decoded": [],
            }
            for s in strings_of(p, 20):
                for how, dec in b64_variants(s):
                    info["decoded"].append([how, dec.decode("latin-1")])
            result.append(info)
        print(_json.dumps(result, ensure_ascii=False, indent=2))
        if args.out:
            open(args.out, "w", encoding="utf-8").write(
                _json.dumps(result, ensure_ascii=False, indent=2))
        return

    report = []
    for p in targets:
        report.append(f"\n=== {p} ===")
        report.extend(inspect(p, args.max_strings))

    text = "\n".join(report)
    print(text)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(text)
        print(f"\n[+] отчёт сохранён: {args.out}")


if __name__ == "__main__":
    main()
