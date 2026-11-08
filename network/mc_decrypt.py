#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
mc_decrypt.py — расшифровать Minecraft-трафик из PCAP по ключу из лога.

Задача-прототип: в логе клиента есть строки
  cipher enabled: AES/CFB8/NoPadding secret=<32 hex>
а в PCAP — зашифрованная сессия. Скрипт сам находит границу шифрования,
перебирает ключи и смещения, парсит пакеты (с zlib), ищет строки и флаги.

  python mc_decrypt.py capture.pcap --log latest.log
  python mc_decrypt.py capture.pcap --secret 5e19... --secret ...
  python mc_decrypt.py capture.pcap --log latest.log --dump packets.jsonl
  python mc_decrypt.py capture.pcap --log latest.log --port 25565 --grep flag

Ограничение: если в PCAP несколько сессий на одном 4-tuple, они склеятся.
Тогда режь pcap по времени (editcap) или запускай на одном соединении.
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
import builtins
import collections
import json
import os
import re
import sys
import zlib

from Crypto.Cipher import AES
from scapy.all import IP, TCP, PcapReader, Raw

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import common


def collect(pcap, port=25565):
    segs = collections.defaultdict(list)
    with PcapReader(pcap) as pr:
        for p in pr:
            if IP not in p or TCP not in p or Raw not in p:
                continue
            ip, t = p[IP], p[TCP]
            if port not in (t.sport, t.dport):
                continue
            segs[(ip.src, t.sport, ip.dst, t.dport)].append((t.seq, bytes(p[Raw].load)))
    return segs


def reassemble(parts):
    if not parts:
        return b""
    base = min(s for s, _ in parts)
    end = max(s + len(d) for s, d in parts)
    buf = bytearray(end - base)
    for seq, data in parts:
        off = seq - base
        buf[off:off + len(data)] = data
    return bytes(buf)


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


def parse_raw(b, limit=100000):
    """Без сжатия: [len][pid][payload]."""
    out, i = [], 0
    while i < len(b) and len(out) < limit:
        ln, i = rv(b, i)
        if ln is None or ln <= 0 or ln > 3_000_000 or i + ln > len(b):
            break
        end = i + ln
        pid, j = rv(b, i)
        if pid is None or pid > 400:
            break
        out.append((pid, b[j:end], False))
        i = end
    return out


def parse_compressed(b, limit=100000):
    """
    После Set Compression: [len][data_len][data], где data_len=0 — без сжатия,
    иначе data = zlib(pid+payload).
    """
    out, i = [], 0
    while i < len(b) and len(out) < limit:
        ln, i = rv(b, i)
        if ln is None or ln <= 0 or ln > 3_000_000 or i + ln > len(b):
            break
        end = i + ln
        dlen, j = rv(b, i)
        if dlen is None or dlen < 0:
            break
        if dlen == 0:
            pid, k = rv(b, j)
            if pid is None or pid > 400:
                break
            out.append((pid, b[k:end], False))
        else:
            try:
                raw = zlib.decompress(b[j:end])
            except zlib.error:
                break
            pid, k = rv(raw, 0)
            if pid is None or pid > 400:
                break
            out.append((pid, raw[k:], True))
        i = end
    return out


def parse_smart(b, limit=100000):
    """
    Смешанный режим (как в реальном протоколе):
      [len][data_len][data]
      data_len == 0  -> data = pid+payload (без сжатия)
      иначе data = zlib(pid+payload)
    Но первый пакет после включения шифрования может быть ещё в старом формате
    [len][pid][payload] (например, Set Compression). Поэтому если после len идёт
    не 0 и не zlib-сигнатура, считаем это pid.
    """
    out, i = [], 0
    while i < len(b) and len(out) < limit:
        ln, i = rv(b, i)
        if ln is None or ln <= 0 or ln > 3_000_000 or i + ln > len(b):
            break
        end = i + ln
        v, j = rv(b, i)
        if v is None:
            break
        if v == 0:
            pid, k = rv(b, j)
            if pid is None or pid > 400:
                break
            out.append((pid, b[k:end], False))
        elif b[j:j + 2] in (b"\x78\x9c", b"\x78\x01", b"\x78\xda", b"\x78\x5e"):
            try:
                raw = zlib.decompress(b[j:end])
            except zlib.error:
                break
            pid, k = rv(raw, 0)
            if pid is None or pid > 400:
                break
            out.append((pid, raw[k:], True))
        elif v <= 400:
            out.append((v, b[j:end], False))
        else:
            break
        i = end
    return out


def parse_packets(b, mode="smart", limit=100000):
    if mode == "raw":
        return parse_raw(b, limit)
    if mode == "compressed":
        return parse_compressed(b, limit)
    return parse_smart(b, limit)


def best_alignment(data, secrets, max_off=800, min_packets=5):
    best = None
    for sec in secrets:
        k = bytes.fromhex(sec)
        for off in range(0, min(max_off, max(0, len(data) - 10))):
            dec = AES.new(k, AES.MODE_CFB, iv=k, segment_size=8).decrypt(data[off:])
            pkts = parse_packets(dec)
            if len(pkts) >= min_packets and (best is None or len(pkts) > best[0]):
                best = (len(pkts), sec, off, dec, pkts)
    return best


def printable(b):
    return "".join(chr(c) if 32 <= c < 127 else "." for c in b)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("pcap")
    ap.add_argument("--log", help="лог клиента, откуда взять secret=...")
    ap.add_argument("--secret", action="append", default=[])
    ap.add_argument("--port", type=int, default=25565)
    ap.add_argument("--dump-dir", help="папка: JSONL со всеми пакетами по направлениям")
    ap.add_argument("--grep", help="искать подстроку в payload")
    ap.add_argument("--strings", type=int, default=15, help="сколько строк показать")
    ap.add_argument("--json", action="store_true")
    common.add_flag_args(ap)
    args = ap.parse_args()
    common.apply_flag_args(args)
    log = builtins.print if not args.json else (lambda *a, **k: None)
    summary = []

    secrets = list(args.secret)
    if args.log:
        txt = open(args.log, encoding="utf-8", errors="replace").read()
        secrets += re.findall(r"secret=([0-9a-fA-F]{32})", txt)
    secrets = list(dict.fromkeys(s.lower() for s in secrets))
    if not secrets:
        ap.error("нужен --log или хотя бы один --secret")
    log(f"[+] ключей: {len(secrets)}")

    segs = collect(args.pcap, args.port)
    dirs = [(key, reassemble(parts)) for key, parts in segs.items()]
    dirs.sort(key=lambda x: -len(x[1]))
    log(f"[+] направлений: {len(dirs)}")

    any_ok = False
    for key, data in dirs:
        if len(data) < 100:
            continue
        best = best_alignment(data, secrets)
        if not best:
            continue
        any_ok = True
        n, sec, off, dec, pkts = best
        ids = collections.Counter(p for p, _, _ in pkts)
        log(f"\n=== {key[0]}:{key[1]} -> {key[2]}:{key[3]} ===")
        log(f"[+] key={sec}  encryption_start={off}  packets={n}")
        log(f"[+] packet ids: {dict(ids.most_common(12))}")
        summary.append({
            "dir": list(key), "key": sec, "offset": off,
            "packets": n, "ids": dict(ids),
        })

        flags = set()
        strings = []
        for pid, payload, comp in pkts:
            for f in common.find_flags(payload):
                flags.add(f)
            for s in re.findall(rb"[ -~]{8,}", payload):
                if len(s) >= 8:
                    strings.append((pid, s))
        if flags:
            log("[!!!] ФЛАГИ:", " | ".join(flags))

        shown = 0
        for pid, s in strings:
            if args.grep and args.grep.encode() not in s:
                continue
            if shown >= args.strings:
                break
            log(f"   pid={pid:3d} {s[:180].decode('utf-8', 'replace')}")
            shown += 1

        if args.dump_dir:
            os.makedirs(args.dump_dir, exist_ok=True)
            fname = (f"pkts_{key[0].replace('.', '-')}_{key[1]}__"
                     f"{key[2].replace('.', '-')}_{key[3]}.jsonl")
            path = os.path.join(args.dump_dir, fname)
            with open(path, "w", encoding="utf-8") as f:
                for pid, payload, comp in pkts:
                    f.write(json.dumps({"dir": list(key), "pid": pid,
                                        "compressed": comp,
                                        "hex": payload.hex()}) + "\n")
            log(f"[+] пакеты: {path}")

        # подсказка: что делать с пакетами
        log("[i] дальше: посмотри частые pid и hex payload; "
            "если это координаты — вытащи их и рендери как картинку.")

    if args.json:
        builtins.print(json.dumps(summary, ensure_ascii=False, indent=2))
        return

    if not any_ok:
        log("[-] ни один ключ/offset не дал валидных пакетов. "
            "Проверь, что это именно Minecraft-протокол и что ключ из той же сессии.")


if __name__ == "__main__":
    main()
