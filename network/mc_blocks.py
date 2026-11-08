#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
mc_blocks.py — вытащить «пиксели» из пакетов установки блоков Minecraft.

Формат, который встречался в задачах: клиент шлёт packet id 66 (Use Item On),
в payload:
    int32 BE  X
    int32 BE  flags: (T1 << 30) | const
    varint    Y
    ...
Тогда col = (X - X0) * 4 + (T1 // 64), row = Y.

  python mc_blocks.py capture.pcap --log latest.log --csv board.csv
  python mc_blocks.py capture.pcap --secret 5e19... --pid 66 --x0 30
  python mc_blocks.py capture.pcap --log latest.log --csv board.csv --raw

Дальше:  python stego/bitmap_font.py board.csv --ascii --png board.png
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
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mc_decrypt import best_alignment, collect, parse_packets, reassemble  # noqa: E402


def rv(b, i):
    v = 0
    for sh in range(0, 35, 7):
        if i >= len(b):
            return None, i
        c = b[i]
        i += 1
        v |= (c & 0x7F) << sh
        if not c & 0x80:
            return v, i
    return None, i


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("pcap")
    ap.add_argument("--log")
    ap.add_argument("--secret", action="append", default=[])
    ap.add_argument("--port", type=int, default=25565)
    ap.add_argument("--pid", type=int, default=66)
    ap.add_argument("--x0", type=int, default=0, help="минимальный X (левый край); подставь по данным")
    ap.add_argument("--csv", required=True)
    ap.add_argument("--raw", action="store_true", help="писать x,y вместо col,row")
    args = ap.parse_args()

    import re
    secrets = list(args.secret)
    if args.log:
        txt = open(args.log, encoding="utf-8", errors="replace").read()
        secrets += re.findall(r"secret=([0-9a-fA-F]{32})", txt)
    secrets = list(dict.fromkeys(s.lower() for s in secrets))
    if not secrets:
        ap.error("нужен --log или --secret")

    segs = collect(args.pcap, args.port)
    best = None  # (count_pid, key, off, pkts)
    for key, parts in segs.items():
        data = reassemble(parts)
        if len(data) < 200:
            continue
        res = best_alignment(data, secrets)
        if not res:
            continue
        n, sec, off, dec, pkts = res
        target = [(pid, pl) for pid, pl, _ in pkts if pid == args.pid]
        if target and (best is None or len(target) > best[0]):
            best = (len(target), key, sec, off, target)

    if not best:
        print("[-] не нашёл пакетов нужного pid")
        return
    n, key, sec, off, target = best
    print(f"[+] {key} key={sec} off={off} packets(pid={args.pid})={n}")

    rows = []
    for pid, pl in target:
        if len(pl) < 10:
            continue
        x = int.from_bytes(pl[0:4], "big")
        flags = int.from_bytes(pl[4:8], "big")
        t1 = flags >> 30            # 0..3
        y, _ = rv(pl, 8)
        if y is None:
            continue
        if args.raw:
            rows.append((x, y))
        else:
            col = (x - args.x0) * 4 + t1
            rows.append((col, y))

    rows = sorted(set(rows))
    with open(args.csv, "w", encoding="utf-8") as f:
        f.write("x,y\n")
        for a, b in rows:
            f.write(f"{a},{b}\n")

    xs = [a for a, _ in rows]
    ys = [b for _, b in rows]
    print(f"[+] точек: {len(rows)}  x: {min(xs)}..{max(xs)}  y: {min(ys)}..{max(ys)}")
    print(f"[+] CSV: {args.csv}")
    print(f"[i] дальше: python stego/bitmap_font.py {args.csv} --ascii --png board.png")


if __name__ == "__main__":
    main()
