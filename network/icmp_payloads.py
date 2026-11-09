#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""icmp_payloads.py — ICMP-пейлоад и скрытые каналы в pcap.

  python icmp_payloads.py capture.pcap
  python icmp_payloads.py capture.pcap --dump payloads
  python icmp_payloads.py capture.pcap --timing-threshold 0.05

Что пробует:
- собрать payload всех ICMP в порядке захвата и декодировать ascii/hex/base64;
- собрать байты из полей id/seq/ttl/tos (скрытый канал в заголовке);
- тайминги: пауза больше порога = 1, меньше = 0 → байты.
"""
from __future__ import annotations

try:
    import sys as _sys
    for _stream in (_sys.stdout, _sys.stderr):
        _stream.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

import argparse
import base64
import os
import sys

from scapy.all import ICMP, IP, PcapReader, Raw

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import common  # noqa: E402


def decode_any(raw: bytes):
    out = []
    if not raw:
        return out
    try:
        text = raw.decode("ascii")
        if text.strip():
            out.append(("ascii", text))
    except UnicodeDecodeError:
        pass
    compact = "".join(ch for ch in raw.decode("latin-1") if ch in "0123456789abcdefABCDEF")
    if len(compact) >= 8 and len(compact) % 2 == 0:
        try:
            out.append(("hex", bytes.fromhex(compact).decode("utf-8", "replace")))
        except ValueError:
            pass
    try:
        text = raw.decode("ascii").strip()
        pad = text + "=" * (-len(text) % 4)
        decoded = base64.b64decode(pad)
        out.append(("base64", decoded.decode("utf-8", "replace")))
    except Exception:
        pass
    return out


def timing_bits(times, threshold):
    if len(times) < 2:
        return b""
    bits = []
    for a, b in zip(times, times[1:]):
        bits.append("1" if (b - a) > threshold else "0")
    bits = bits[: len(bits) - len(bits) % 8]
    return bytes(int("".join(bits[i:i + 8]), 2) for i in range(0, len(bits), 8))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("pcap")
    ap.add_argument("--dump", help="куда сохранить payload-файлы")
    ap.add_argument("--timing-threshold", type=float, default=0.02,
                    help="порог паузы в секундах (по умолчанию 0.02)")
    common.add_flag_args(ap)
    args = ap.parse_args()
    common.apply_flag_args(args)

    if not os.path.isfile(args.pcap):
        print(f"[-] нет файла: {args.pcap}")
        return
    if args.dump:
        os.makedirs(args.dump, exist_ok=True)

    payloads, times, ids, seqs, ttls, tos = [], [], [], [], [], []
    n = 0
    try:
        with PcapReader(args.pcap) as pr:
            for pkt in pr:
                if ICMP not in pkt or IP not in pkt:
                    continue
                n += 1
                ip = pkt[IP]
                icmp = pkt[ICMP]
                times.append(float(getattr(pkt, "time", 0.0)))
                ids.append(int(icmp.id) & 0xFFFF)
                seqs.append(int(icmp.seq) & 0xFFFF)
                ttls.append(int(ip.ttl))
                tos.append(int(ip.tos))
                if Raw in pkt:
                    payloads.append(bytes(pkt[Raw].load))
    except Exception as e:
        print(f"[-] не прочитать pcap: {e}")
        return

    if not n:
        print("[-] ICMP-пакетов нет")
        return
    print(f"[i] ICMP-пакетов: {n}, с payload: {len(payloads)}")
    print(f"[i] id: {len(set(ids))} уникальных, seq: {min(seqs)}..{max(seqs)}")

    joined = b"".join(payloads)
    if joined:
        print(f"[i] payload всего: {len(joined)} байт")
        for how, text in decode_any(joined):
            clean = text.strip()
            if not clean:
                continue
            print(f"[+] {how}: {clean[:300]}")
            for f in common.find_flags(clean.encode("utf-8", "replace")):
                print(f"[!!!] ФЛАГ: {f}")
        if args.dump:
            dst = os.path.join(args.dump, "icmp_payload.bin")
            open(dst, "wb").write(joined)
            print(f"[i] сохранено: {dst}")

    # скрытый канал в полях заголовка
    for label, values in (("id", ids), ("seq", seqs), ("ttl", ttls), ("tos", tos)):
        raw = bytes(v & 0xFF for v in values)
        for how, text in decode_any(raw):
            clean = text.strip()
            if clean and len(clean) >= 4:
                print(f"[+] {label}/{how}: {clean[:200]}")
                for f in common.find_flags(clean.encode()):
                    print(f"[!!!] ФЛАГ ({label}): {f}")

    # тайминги
    bits = timing_bits(times, args.timing_threshold)
    if bits:
        for how, text in decode_any(bits):
            clean = text.strip()
            if clean and len(clean) >= 4:
                print(f"[+] timing/{how}: {clean[:200]}")
                for f in common.find_flags(clean.encode()):
                    print(f"[!!!] ФЛАГ (timing): {f}")


if __name__ == "__main__":
    main()
