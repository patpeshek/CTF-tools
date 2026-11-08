#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
pcap_report.py — отчёт по PCAP без Wireshark (scapy): протоколы, разговоры,
DNS, HTTP, ICMP-payload, base64/флаги в данных. Плюс дамп потоков.

  python pcap_report.py capture.pcap
  python pcap_report.py capture.pcap --dump streams
  python pcap_report.py capture.pcap --grep activation_code
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
import os
import re
from collections import Counter, defaultdict

from scapy.all import IP, TCP, UDP, ICMP, DNS, Raw, PcapReader

FLAG = re.compile(rb"(?:CTF|ctf|flag)\{[^}\r\n]{1,200}\}")
B64 = re.compile(rb"[A-Za-z0-9+/]{16,}={0,2}")
TEXT = re.compile(rb"[\x20-\x7e]{5,}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("pcap")
    ap.add_argument("--dump", help="папка для дампа TCP-потоков")
    ap.add_argument("--grep", help="искать подстроку в payload")
    ap.add_argument("--max-packets", type=int, default=0, help="остановиться после N пакетов")
    args = ap.parse_args()

    proto = Counter()
    conv = Counter()
    dns_q = []
    http = []
    icmp_payload = []
    flags = set()
    b64 = Counter()
    streams = defaultdict(bytearray)
    total = 0

    with PcapReader(args.pcap) as pr:
        for pkt in pr:
            total += 1
            if args.max_packets and total > args.max_packets:
                break
            if IP in pkt:
                ip = pkt[IP]
                conv[(ip.src, ip.dst)] += 1
                if TCP in pkt:
                    proto["TCP"] += 1
                    t = pkt[TCP]
                    if t.dport in (80, 8080, 8000, 3000, 5000) or t.sport in (80, 8080, 8000, 3000, 5000):
                        proto["HTTP?"] += 1
                    key = tuple(sorted([(ip.src, t.sport), (ip.dst, t.dport)]))
                    if Raw in pkt:
                        streams[key] += bytes(pkt[Raw].load)
                elif UDP in pkt:
                    proto["UDP"] += 1
                    if DNS in pkt and pkt[DNS].qd is not None:
                        try:
                            dns_q.append(pkt[DNS].qd.qname.decode("utf-8", "replace"))
                        except Exception:
                            pass
                elif ICMP in pkt:
                    proto["ICMP"] += 1
                    if Raw in pkt:
                        icmp_payload.append(bytes(pkt[Raw].load))
                else:
                    proto["IP-other"] += 1

                if Raw in pkt:
                    payload = bytes(pkt[Raw].load)
                    for f in FLAG.findall(payload):
                        flags.add(f.decode("utf-8", "replace"))
                    if payload.startswith((b"GET ", b"POST ", b"PUT ", b"HTTP/")):
                        first = payload.split(b"\r\n", 1)[0]
                        http.append(first[:120])
                    for m in B64.finditer(payload):
                        if len(m.group()) >= 24:
                            b64[m.group()[:80]] += 1
                    if args.grep and args.grep.encode() in payload:
                        print(f"[grep] {ip.src} -> {ip.dst}: {payload[:300]!r}")

    print(f"=== Всего пакетов: {total} ===")
    print("Протоколы:", dict(proto))
    print("\nТоп разговоров:")
    for (a, b), n in conv.most_common(10):
        print(f"  {a:15s} -> {b:15s} {n}")

    if dns_q:
        print("\nDNS-запросы (первые 30):")
        for q in dns_q[:30]:
            print("  ", q)

    if http:
        print("\nHTTP-строки (первые 30):")
        for h in http[:30]:
            print("  ", h.decode("utf-8", "replace"))

    if icmp_payload:
        print("\nICMP payload (первые 5, hex):")
        for p in icmp_payload[:5]:
            print("  ", p[:80].hex())
        joined = b"".join(icmp_payload)
        try:
            print("  как текст:", joined.decode("utf-8", "replace")[:300])
        except Exception:
            pass

    if flags:
        print("\n[!!!] ФЛАГИ:", " | ".join(flags))

    if b64:
        print("\nbase64-кандидаты:")
        for cand, n in b64.most_common(10):
            dec = b""
            try:
                dec = base64.b64decode(cand + b"=" * (-len(cand) % 4))
            except Exception:
                pass
            shown = dec[:80] if dec else b""
            print(f"  x{n} {cand[:60]!r} -> {shown!r}")

    if args.dump:
        os.makedirs(args.dump, exist_ok=True)
        for i, (key, data) in enumerate(streams.items()):
            if data:
                fname = os.path.join(args.dump, f"stream_{i:03d}.bin")
                open(fname, "wb").write(data)
        print(f"\n[+] потоков сохранено: {len(streams)} -> {args.dump}")
        print("    далее: strings stream_*.bin | grep -i flag")


if __name__ == "__main__":
    try:
        main()
    except (FileNotFoundError, IsADirectoryError, PermissionError) as e:
        print(f"[-] не могу открыть: {getattr(e, 'filename', None) or e}")
    except BrokenPipeError:
        pass
    except KeyboardInterrupt:
        print("\n[-] прервано")
