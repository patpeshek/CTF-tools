#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
udp_payloads.py — вытащить UDP-payload из PCAP и разобрать самодельный протокол.

Типовой кейс: в пакетах лежит ASCII-строка вида
    MOBILE/<uuid>/<nonce>/<ciphertext>
где поля — hex/base64. Скрипт печатает поля и пробует декодировать.

  python udp_payloads.py capture.pcap
  python udp_payloads.py capture.pcap --sep "/" --signature MOBILE/
  python udp_payloads.py capture.pcap --dump payloads
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

from scapy.all import IP, UDP, PcapReader, Raw

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import common


def try_decode(field: str):
    out = []
    s = field.strip()
    try:
        out.append(("hex", bytes.fromhex(s)))
    except ValueError:
        pass
    try:
        out.append(("b64", base64.b64decode(s + "=" * (-len(s) % 4))))
    except Exception:
        pass
    out.append(("raw", s.encode()))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("pcap")
    ap.add_argument("--sep", default="/")
    ap.add_argument("--signature")
    ap.add_argument("--port", type=int)
    ap.add_argument("--dump")
    common.add_flag_args(ap)
    args = ap.parse_args()
    common.apply_flag_args(args)

    if args.dump:
        os.makedirs(args.dump, exist_ok=True)

    n = 0
    with PcapReader(args.pcap) as pr:
        for pkt in pr:
            if UDP not in pkt or Raw not in pkt:
                continue
            ip = pkt[IP] if IP in pkt else None
            u = pkt[UDP]
            if args.port and args.port not in (u.sport, u.dport):
                continue
            data = bytes(pkt[Raw].load)
            text = None
            try:
                text = data.decode("ascii")
            except UnicodeDecodeError:
                pass

            if args.signature and args.signature.encode() not in data:
                continue

            n += 1
            print(f"\n=== #{n} {ip.src if ip else '?'}:{u.sport} -> "
                  f"{ip.dst if ip else '?'}:{u.dport}  {len(data)} b ===")
            print("hex:", data[:96].hex())
            print("asc:", "".join(chr(c) if 32 <= c < 127 else "." for c in data[:160]))

            if text and args.sep in text:
                fields = text.split(args.sep)
                print("поля:", fields)
                for i, f in enumerate(fields):
                    for how, dec in try_decode(f):
                        if dec and all(32 <= c < 127 or c in (9, 10, 13) for c in dec[:40]):
                            print(f"  [{i}] {how}: {dec[:120]!r}")

            for f in common.find_flags(data):
                print("[!!!] FLAG:", f)

            if args.dump:
                open(os.path.join(args.dump, f"udp_{n:03d}.bin"), "wb").write(data)

    print(f"\n[+] UDP-пакетов: {n}")


if __name__ == "__main__":
    try:
        main()
    except (FileNotFoundError, IsADirectoryError, PermissionError) as e:
        print(f"[-] не могу открыть: {getattr(e, 'filename', None) or e}")
    except BrokenPipeError:
        pass
    except KeyboardInterrupt:
        print("\n[-] прервано")
