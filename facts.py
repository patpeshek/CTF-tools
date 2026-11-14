#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""facts.py — факты о файле, а не готовый рецепт.

Это «глаза» решателя: по одному файлу печатает то, что помогает понять
задачу — реальный тип по magic, размер, энтропию, числа с метками и
разрядностью, кодировки, архивы, картинки, PDF-ревизии, SQLite, строки.

    python facts.py file.bin
    python facts.py file.bin --json

Ничего не меняет на диске.
"""
from __future__ import annotations

try:
    import sys as _sys
    for _s in (_sys.stdout, _sys.stderr):
        _s.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

import argparse
import base64
import collections
import hashlib
import json
import math
import os
import re
import sqlite3
import tarfile
import zipfile

MAGICS = [
    (b"\x89PNG\r\n\x1a\n", "PNG"),
    (b"\xff\xd8\xff", "JPEG"),
    (b"GIF87a", "GIF"),
    (b"GIF89a", "GIF"),
    (b"PK\x03\x04", "ZIP"),
    (b"PK\x05\x06", "ZIP (empty)"),
    (b"\x1f\x8b", "GZIP"),
    (b"BZh", "BZIP2"),
    (b"\xfd7zXZ\x00", "XZ"),
    (b"7z\xbc\xaf\x27\x1c", "7Z"),
    (b"Rar!\x1a\x07", "RAR"),
    (b"%PDF", "PDF"),
    (b"\x7fELF", "ELF"),
    (b"MZ", "PE"),
    (b"SQLite format 3\x00", "SQLite"),
    (b"RIFF", "RIFF"),
    (b"ID3", "MP3 (ID3)"),
    (b"OggS", "OGG"),
    (b"fLaC", "FLAC"),
    (b"\xd4\xc3\xb2\xa1", "PCAP"),
    (b"\xa1\xb2\xc3\xd4", "PCAP"),
    (b"\x0a\x0d\x0d\x0a", "PCAPNG"),
    (b"{\\rtf", "RTF"),
    (b"ustar", "TAR"),
]

LABEL_RE = re.compile(
    r"(?im)\b(n|e|d|p|q|phi|dp|dq|modulus|exponent|c|cipher|ct|ciphertext|"
    r"nonce|iv|key)\b\s*[=:]\s*(0x[0-9a-fA-F]+|\d{2,})")
NUM_RE = re.compile(r"(?<![0-9a-fA-Fx])(\d{20,})(?![0-9a-fA-F])")
HEX_RE = re.compile(rb"(?:0x)?[0-9a-fA-F]{24,}")
B64_RE = re.compile(rb"[A-Za-z0-9+/]{24,}={0,2}")


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    c = collections.Counter(data)
    n = len(data)
    return round(-sum(v / n * math.log2(v / n) for v in c.values()), 2)


def printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    return round(sum(32 <= b < 127 or b in (9, 10, 13) for b in data) / len(data), 2)


def decode_text(raw: bytes) -> tuple[str, str] | None:
    for enc in ("utf-8", "utf-16-le", "utf-16-be", "cp1251"):
        try:
            txt = raw.decode(enc)
        except Exception:
            continue
        letters = sum(ch.isalpha() for ch in txt)
        printable = sum(ch.isprintable() or ch in "\n\r\t" for ch in txt)
        if (letters >= max(4, len(txt) * 0.15)
                and printable / max(1, len(txt)) >= 0.85):
            return enc, txt
    return None


def numbers(text: str) -> dict:
    out = {"labeled": [], "big": []}
    for m in LABEL_RE.finditer(text):
        raw = m.group(2)
        try:
            val = int(raw, 0)
        except ValueError:
            continue
        out["labeled"].append({"label": m.group(1).lower(), "bits": val.bit_length()})
        if len(out["labeled"]) >= 12:
            break
    big = []
    for m in NUM_RE.finditer(text):
        raw = m.group(1)
        if raw not in big:
            big.append(raw)
        if len(big) >= 12:
            break
    out["big"] = [{"digits": len(x), "bits": int(x).bit_length()} for x in big]
    return out


def archives(path: str) -> dict | None:
    if zipfile.is_zipfile(path):
        try:
            with zipfile.ZipFile(path) as z:
                infos = z.infolist()
                return {"kind": "zip", "entries": len(infos),
                        "encrypted": any(i.flag_bits & 1 for i in infos),
                        "names": [i.filename for i in infos[:15]]}
        except Exception:
            return None
    try:
        if tarfile.is_tarfile(path):
            with tarfile.open(path) as t:
                names = t.getnames()
                return {"kind": "tar", "entries": len(names),
                        "names": names[:15]}
    except Exception:
        pass
    return None


def image(path: str) -> dict | None:
    try:
        from PIL import Image
    except Exception:
        return None
    try:
        with Image.open(path) as im:
            info = {"format": im.format, "size": list(im.size), "mode": im.mode}
            if im.mode in ("P", "PA"):
                info["palette"] = len(im.getpalette() or []) // 3
            if getattr(im, "n_frames", 1) > 1:
                info["frames"] = im.n_frames
            return info
    except Exception:
        return None


def pdf(path: str) -> dict | None:
    with open(path, "rb") as f:
        raw = f.read(8_000_000)
    if not raw.startswith(b"%PDF"):
        return None
    return {"revisions": raw.count(b"%%EOF"),
            "streams": raw.count(b"stream"),
            "objects": len(re.findall(rb"\d+\s+\d+\s+obj", raw))}


def sqlite(path: str) -> dict | None:
    if not path.lower().endswith((".db", ".sqlite", ".sqlite3")):
        return None
    try:
        con = sqlite3.connect("file:%s?mode=ro&immutable=1" % path, uri=True)
        try:
            rows = con.execute(
                "select name from sqlite_master where type='table'").fetchall()
            pages = con.execute("pragma page_count").fetchone()
            size = con.execute("pragma page_size").fetchone()
            return {"tables": [r[0] for r in rows][:15],
                    "pages": pages[0] if pages else None,
                    "page_size": size[0] if size else None}
        finally:
            con.close()
    except Exception:
        return None


def trailing_ws_lines(raw: bytes, limit: int = 5000) -> int:
    count = 0
    for line in raw.split(b"\n")[:limit]:
        line = line.rstrip(b"\r")
        if line and line[-1:] in (b" ", b"\t"):
            count += 1
    return count


def strings(raw: bytes, limit: int = 8) -> list[dict]:
    out = []
    for m in re.finditer(rb"[\x20-\x7e]{6,}", raw[:4_000_000]):
        out.append({"offset": m.start(), "text": m.group().decode("latin-1")[:80]})
        if len(out) >= limit:
            break
    return out


def utf16_strings(raw: bytes, limit: int = 6) -> list[dict]:
    """UTF-16LE строки: теги ID3, метаданные, «широкие» строки в бинарниках."""
    out = []
    for m in re.finditer(rb"(?:[\x20-\x7e]\x00){6,}", raw[:4_000_000]):
        out.append({"offset": m.start(),
                    "text": m.group().decode("utf-16-le", "replace")[:80]})
        if len(out) >= limit:
            break
    return out


def build(path: str) -> dict:
    size = os.path.getsize(path)
    with open(path, "rb") as f:
        raw = f.read(1_000_000)
    head = raw[:512]
    kind = "unknown"
    for sig, name in MAGICS:
        if head.startswith(sig):
            kind = name
            break
    if kind == "unknown" and b"ustar" in head:
        kind = "TAR"
    info = {
        "path": os.path.basename(path),
        "size": size,
        "sha256": hashlib.sha256(raw).hexdigest()[:16],
        "type": kind,
        "ext": os.path.splitext(path)[1].lower(),
        "first_bytes": head[:32].hex(" "),
        "entropy": entropy(raw),
        "printable": printable_ratio(raw),
        "trailing_ws_lines": trailing_ws_lines(raw),
    }
    dec = decode_text(raw)
    if dec:
        enc, txt = dec
        info["text"] = enc
        info["numbers"] = numbers(txt[:500_000])
        b64 = [m.group().decode("latin-1") for m in B64_RE.finditer(raw[:500_000])]
        hexes = [m.group().decode("latin-1") for m in HEX_RE.finditer(raw[:500_000])]
        info["b64"] = {"count": len(b64), "longest": max((len(x) for x in b64), default=0)}
        info["hex"] = {"count": len(hexes), "longest": max((len(x) for x in hexes), default=0)}
    else:
        info["text"] = None
    for name, fn in (("archive", archives), ("image", image),
                     ("pdf", pdf), ("sqlite", sqlite)):
        val = fn(path)
        if val:
            info[name] = val
    if kind in ("unknown", "ZIP", "PCAP", "MP3 (ID3)", "PDF", "SQLite"):
        info["strings"] = strings(raw)
        utf16 = utf16_strings(raw)
        if utf16:
            info["strings_utf16"] = utf16
    return info


def show(info: dict) -> None:
    print(f"[facts] {info['path']}: {info['size']} байт, sha256={info['sha256']}")
    print(f"  тип по magic: {info['type']} (расширение {info['ext'] or '—'})")
    print(f"  энтропия: {info['entropy']} бит/байт"
          + ("  ← сжато/шифровано" if info["entropy"] > 7.5 else ""))
    print(f"  печатаемых: {info['printable']}; текст: {info['text'] or 'нет'}")
    if info.get("trailing_ws_lines"):
        print(f"  строк с хвостовыми пробелами/табами: {info['trailing_ws_lines']}")
    nums = info.get("numbers") or {}
    if nums.get("labeled"):
        print("  числа с метками: " + ", ".join(
            f"{x['label']}={x['bits']} бит" for x in nums["labeled"][:8]))
    if nums.get("big"):
        print("  большие числа: " + ", ".join(
            f"{x['digits']} цифр/{x['bits']} бит" for x in nums["big"][:8]))
    if info.get("b64", {}).get("count"):
        print(f"  base64: {info['b64']['count']} (длиннейший {info['b64']['longest']})")
    if info.get("hex", {}).get("count"):
        print(f"  hex: {info['hex']['count']} (длиннейший {info['hex']['longest']})")
    if info.get("archive"):
        a = info["archive"]
        print(f"  архив: {a['entries']} файлов"
              + (", ШИФРОВАН" if a.get("encrypted") else "")
              + (": " + ", ".join(a["names"][:8]) if a.get("names") else ""))
    if info.get("image"):
        im = info["image"]
        print(f"  картинка: {im['format']} {im['size'][0]}x{im['size'][1]} "
              f"{im['mode']}" + (f", палитра {im['palette']}" if im.get("palette") else "")
              + (f", кадров {im['frames']}" if im.get("frames") else ""))
    if info.get("pdf"):
        p = info["pdf"]
        print(f"  PDF: ревизий {p['revisions']}, потоков {p['streams']}, объектов {p['objects']}")
    if info.get("sqlite"):
        s = info["sqlite"]
        print(f"  SQLite: таблицы {', '.join(s['tables'][:6])}; "
              f"страниц {s['pages']} по {s['page_size']}")
    if info.get("strings"):
        print("  строки:")
        for s in info["strings"][:8]:
            print(f"    @{s['offset']:#08x} {s['text']}")
    if info.get("strings_utf16"):
        print("  UTF-16 строки:")
        for s in info["strings_utf16"][:6]:
            print(f"    @{s['offset']:#08x} {s['text']}")
    print(f"  первые байты: {info['first_bytes']}")


def main():
    ap = argparse.ArgumentParser(description="факты о файле")
    ap.add_argument("file")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    if not os.path.isfile(args.file):
        print(f"[-] нет файла: {args.file}")
        return
    info = build(args.file)
    if args.json:
        print(json.dumps(info, ensure_ascii=False, indent=1))
    else:
        show(info)


if __name__ == "__main__":
    main()
