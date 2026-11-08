#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
pcap_http.py — вытащить HTTP-запросы и тела ответов из PCAP.

  python pcap_http.py capture.pcap
  python pcap_http.py capture.pcap --out http_objects
  python pcap_http.py capture.pcap --all-ports

Собирает TCP по seq, ищет начала запросов/ответов, парсит Content-Length,
складывает тела в файлы.
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

from scapy.all import IP, TCP, PcapReader, Raw

METHODS = (b"GET ", b"POST ", b"PUT ", b"HEAD ", b"DELETE ", b"OPTIONS ", b"PATCH ")
STATUS = re.compile(rb"^HTTP/\d\.\d (\d{3})")


def collect(pcap, port):
    segs = {}
    with PcapReader(pcap) as pr:
        for p in pr:
            if IP not in p or TCP not in p or Raw not in p:
                continue
            t = p[TCP]
            if port and port not in (t.sport, t.dport):
                continue
            key = (p[IP].src, t.sport, p[IP].dst, t.dport)
            segs.setdefault(key, []).append((t.seq, bytes(p[Raw].load)))
    out = {}
    for key, parts in segs.items():
        base = min(s for s, _ in parts)
        end = max(s + len(d) for s, d in parts)
        buf = bytearray(end - base)
        for s, d in parts:
            buf[s - base:s - base + len(d)] = d
        out[key] = bytes(buf)
    return out


def parse_stream(data, ext_by_type=True):
    """Возвращает список (kind, first_line, headers, body)."""
    items = []
    i = 0
    while i < len(data):
        starts = []
        for m in METHODS:
            pos = data.find(m, i)
            if pos != -1:
                starts.append(pos)
        hpos = data.find(b"HTTP/", i)
        if hpos != -1:
            starts.append(hpos)
        if not starts:
            break
        start = min(starts)
        hdr_end = data.find(b"\r\n\r\n", start)
        if hdr_end == -1:
            break
        head = data[start:hdr_end]
        body_start = hdr_end + 4
        headers = {}
        lines = head.split(b"\r\n")
        first = lines[0].decode("latin-1", "replace")
        for line in lines[1:]:
            if b":" in line:
                k, v = line.split(b":", 1)
                headers[k.strip().lower().decode("latin-1", "replace")] = \
                    v.strip().decode("latin-1", "replace")
        length = headers.get("content-length")
        body = b""
        if length and length.isdigit():
            body = data[body_start:body_start + int(length)]
        kind = "request" if first.split(" ")[0] in (
            "GET", "POST", "PUT", "HEAD", "DELETE", "OPTIONS", "PATCH") else "response"
        items.append((kind, first, headers, body))
        i = body_start + (int(length) if length and length.isdigit() else 0)
        if i <= start:
            i = start + 1
    return items


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("pcap")
    ap.add_argument("--port", type=int, default=80)
    ap.add_argument("--all-ports", action="store_true")
    ap.add_argument("--out")
    args = ap.parse_args()

    port = None if args.all_ports else args.port
    streams = collect(args.pcap, port)
    n = 0
    for key, data in streams.items():
        if len(data) < 16:
            continue
        items = parse_stream(data)
        if not items:
            continue
        print(f"\n=== {key[0]}:{key[1]} -> {key[2]}:{key[3]}  {len(data)} b ===")
        for kind, first, headers, body in items:
            n += 1
            print(f"  [{kind}] {first[:140]}")
            if headers.get("content-type"):
                print(f"      type: {headers['content-type']}")
            if body:
                print(f"      body: {len(body)} b  head={body[:80]!r}")
                if args.out:
                    os.makedirs(args.out, exist_ok=True)
                    ctype = headers.get("content-type", "")
                    ext = ".bin"
                    for token, e in (("json", ".json"), ("html", ".html"),
                                     ("javascript", ".js"), ("image/png", ".png"),
                                     ("image/jpeg", ".jpg"), ("text", ".txt")):
                        if token in ctype:
                            ext = e
                            break
                    path = os.path.join(args.out, f"obj_{n:03d}{ext}")
                    open(path, "wb").write(body)
    print(f"\n[+] объектов: {n}")


if __name__ == "__main__":
    try:
        main()
    except (FileNotFoundError, IsADirectoryError, PermissionError) as e:
        print(f"[-] не могу открыть: {getattr(e, 'filename', None) or e}")
    except BrokenPipeError:
        pass
    except KeyboardInterrupt:
        print("\n[-] прервано")
