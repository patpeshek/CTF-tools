#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
tcp_reassemble.py — сборка TCP-потоков по sequence numbers (без Wireshark).

  python tcp_reassemble.py capture.pcap
  python tcp_reassemble.py capture.pcap --dump streams
  python tcp_reassemble.py capture.pcap --port 25565 --dump streams

Каждое направление (src:sport -> dst:dport) собирается отдельно, с учётом
retransmission и порядка пакетов. В --dump кладутся файлы stream_XX_ab.bin.
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
import collections
import os

from scapy.all import IP, TCP, PcapReader, Raw


def collect(pcap, port=None):
    segs = collections.defaultdict(list)
    with PcapReader(pcap) as pr:
        for p in pr:
            if IP not in p or TCP not in p or Raw not in p:
                continue
            ip, t = p[IP], p[TCP]
            if port and port not in (t.sport, t.dport):
                continue
            key = (ip.src, t.sport, ip.dst, t.dport)
            segs[key].append((t.seq, bytes(p[Raw].load)))
    return segs


def reassemble(segments):
    """Собирает поток по seq. Возвращает (bytes, gaps)."""
    if not segments:
        return b"", 0
    base = min(s for s, _ in segments)
    end = max(s + len(d) for s, d in segments)
    size = end - base
    buf = bytearray(size)
    filled = bytearray(size)
    gaps = 0
    for seq, data in segments:
        off = seq - base
        if off < 0 or off + len(data) > size:
            continue
        buf[off:off + len(data)] = data
        for i in range(off, off + len(data)):
            filled[i] = 1
    gaps = filled.count(0)
    return bytes(buf), gaps


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("pcap")
    ap.add_argument("--port", type=int)
    ap.add_argument("--dump")
    args = ap.parse_args()

    segs = collect(args.pcap, args.port)
    streams = []
    for key, parts in segs.items():
        data, gaps = reassemble(parts)
        streams.append((key, data, gaps, len(parts)))

    streams.sort(key=lambda x: -len(x[1]))
    print(f"направлений: {len(streams)}")
    for key, data, gaps, n in streams[:20]:
        print(f"  {key[0]}:{key[1]} -> {key[2]}:{key[3]}  {len(data)} b  "
              f"сегментов={n}  дыр={gaps}")

    if args.dump:
        os.makedirs(args.dump, exist_ok=True)
        for i, (key, data, gaps, n) in enumerate(streams):
            name = f"stream_{i:02d}_{key[0].replace('.', '-')}_{key[1]}__{key[2].replace('.', '-')}_{key[3]}.bin"
            path = os.path.join(args.dump, name)
            open(path, "wb").write(data)
            print(f"  -> {path}")


if __name__ == "__main__":
    try:
        main()
    except (FileNotFoundError, IsADirectoryError, PermissionError) as e:
        print(f"[-] не могу открыть: {getattr(e, 'filename', None) or e}")
    except BrokenPipeError:
        pass
    except KeyboardInterrupt:
        print("\n[-] прервано")
