#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
pdf_revisions.py — текст из ВСЕХ ревизий PDF (инкрементальные обновления).

  python pdf_revisions.py contract.pdf
  python pdf_revisions.py contract.pdf --json
  python pdf_revisions.py contract.pdf --min-len 4

Инкрементальное обновление (`…%%EOF` + новый xref с /Prev) дописывает объекты
в конец файла, а старые остаются внутри — просто не адресуются из свежего xref.
Поэтому «замазанный» ([REDACTED]) текст обычно живёт в предыдущей ревизии.
Скрипт разбирает ВСЕ потоки stream…endstream (в том числе перекрытые),
снимает FlateDecode/ASCIIHex/ASCII85 и достаёт строки из Tj/TJ/'/".
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
import json
import os
import re
import sys
import zlib

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import common  # noqa: E402

STREAM_RE = re.compile(rb"stream\r?\n")
OBJ_RE = re.compile(rb"(\d+)\s+(\d+)\s+obj")
FILTER_RE = re.compile(rb"/Filter\s*(\[[^\]]*\]|/\w+)")
PAREN_RE = re.compile(rb"\((?:\\.|[^\\()])*\)", re.S)
HEXSTR_RE = re.compile(rb"<([0-9A-Fa-f\s]{4,})>")
ESCAPES = {b"n": b"\n", b"r": b"\r", b"t": b"\t", b"b": b"\b",
           b"f": b"\f", b"(": b"(", b")": b")", b"\\": b"\\"}


def unescape(raw: bytes) -> bytes:
    """Снять PDF-экранирование со строки в скобках."""
    out = bytearray()
    i = 0
    while i < len(raw):
        c = raw[i:i + 1]
        if c != b"\\":
            out += c
            i += 1
            continue
        nxt = raw[i + 1:i + 2]
        if nxt in ESCAPES:
            out += ESCAPES[nxt]
            i += 2
        elif nxt.isdigit():                     # \053 — восьмеричный код
            octal = re.match(rb"[0-7]{1,3}", raw[i + 1:i + 4])
            out.append(int(octal.group(), 8) & 0xFF)
            i += 1 + len(octal.group())
        elif nxt in (b"\r", b"\n"):             # перенос строки внутри строки
            i += 2
        else:
            out += nxt
            i += 2
    return bytes(out)


def decode_stream(blob: bytes, filters: bytes) -> bytes:
    """Снять фильтры потока: FlateDecode, ASCIIHexDecode, ASCII85Decode."""
    data = blob
    names = re.findall(rb"/(\w+)", filters or b"")
    for name in names:
        if name in (b"FlateDecode", b"Fl"):
            for wbits in (zlib.MAX_WBITS, -zlib.MAX_WBITS):
                try:
                    data = zlib.decompress(data, wbits)
                    break
                except zlib.error:
                    continue
            else:
                return b""                      # битый поток — пропускаем
        elif name in (b"ASCIIHexDecode", b"AHx"):
            try:
                data = bytes.fromhex(re.sub(rb"[^0-9A-Fa-f]", b"", data).decode())
            except ValueError:
                return b""
        elif name in (b"ASCII85Decode", b"A85"):
            try:
                data = base64.a85decode(data, adobe=True)
            except Exception:
                try:
                    data = base64.a85decode(data)
                except Exception:
                    return b""
    return data


def stream_text(data: bytes) -> str:
    """Строки из контента потока: (…) и <hex>, плюс печатные куски как есть."""
    out = []
    for m in PAREN_RE.finditer(data):
        out.append(unescape(m.group()[1:-1]))
    for m in HEXSTR_RE.finditer(data):
        hx = re.sub(rb"\s", b"", m.group(1))
        if len(hx) % 2 == 0:
            try:
                out.append(bytes.fromhex(hx.decode()))
            except ValueError:
                pass
    text = b" ".join(x for x in out if x)
    if not text and common.printable_ratio(data) >= 0.85:
        text = data
    return text.decode("utf-8", "replace")


def revisions(data: bytes):
    """[(подпись, текст)] по всем потокам, включая перекрытые ревизиями."""
    out = []
    for m in STREAM_RE.finditer(data):
        start = m.end()
        end = data.find(b"endstream", start)
        if end < 0:
            continue
        head = data[max(0, m.start() - 600):m.start()]
        f = FILTER_RE.search(head)
        filters = f.group(1) if f else b""
        raw = data[start:end].rstrip(b"\r\n")
        body = decode_stream(raw, filters) if filters else raw
        if not body:
            continue
        obj = None
        for om in OBJ_RE.finditer(head):
            obj = om
        label = f"{obj.group(1).decode()} {obj.group(2).decode()} obj" if obj else "stream"
        label += f" @0x{m.start():x}"
        if filters:
            label += f" [{filters.decode('latin-1')}]"
        out.append((label, stream_text(body), body))
    return out


def main():
    ap = argparse.ArgumentParser(description="текст из всех ревизий PDF")
    ap.add_argument("file")
    ap.add_argument("--min-len", type=int, default=2, help="короче — не печатать")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--raw", action="store_true", help="печатать и разжатые байты")
    args = ap.parse_args()

    data = open(args.file, "rb").read()
    revs = revisions(data)
    print(f"[+] файл: {args.file} ({len(data)} b), потоков: {len(revs)}")
    flags = []
    for label, text, body in revs:
        text = text.strip()
        if len(text) < args.min_len:
            continue
        print(f"\n--- {label} ({len(text)} символов)")
        print(text[:2000])
        if args.raw:
            print(f"    bytes: {body[:300]!r}")
        for fl in common.find_flags(text.encode("utf-8", "replace")):
            flags.append(fl)
            print(f"[FLAG] {fl}   ({label})")
    if len(revs) > 1:
        print(f"\n[i] потоков больше одного ({len(revs)}): так выглядят "
              "инкрементальные обновления — сверь ревизии, старая могла остаться")
    if flags:
        print("[+] флаги: " + ", ".join(dict.fromkeys(flags)))
    if args.json:
        print(json.dumps([{"where": l, "text": t} for l, t, _ in revs],
                         ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (FileNotFoundError, IsADirectoryError, PermissionError) as e:
        print(f"[-] не могу открыть: {getattr(e, 'filename', None) or e}")
    except BrokenPipeError:
        pass
    except KeyboardInterrupt:
        print("\n[-] прервано")
