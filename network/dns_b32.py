#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
dns_b32.py — собрать данные из DNS-меток (base32/base64/hex) по номерам.

  python dns_b32.py night.pcap
  python dns_b32.py night.pcap --json

Зачем: в задачах экфильтрация идёт метками вида `00-<base32>`,
`01-<base32>`, … (`00-inkem6zyg…silver.baker`). По одной метке base32 не
декодируется (нет выравнивания), а **склеенные по номеру** — дают текст.
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
import json
import re
import struct
import sys

LABEL_RX = re.compile(r"^(?:\d{1,3}[-_.])?([a-z0-9]{8,})$", re.I)
HEX_RX = re.compile(r"^[0-9a-f]{8,}$", re.I)


def _read_name(msg: bytes, pos: int, depth: int = 0):
    labels = []
    while pos < len(msg) and depth < 20:
        ln = msg[pos]
        if ln == 0:
            pos += 1
            break
        if ln & 0xC0:
            ptr = struct.unpack_from(">H", msg, pos)[0] & 0x3FFF
            sub, _ = _read_name(msg, ptr, depth + 1)
            if sub:
                labels.append(sub)
            pos += 2
            break
        labels.append(msg[pos + 1:pos + 1 + ln].decode("latin-1", "replace"))
        pos += 1 + ln
    return ".".join(labels), pos


def dns_queries(data: bytes):
    magic = data[:4]
    if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        endian = "<"
    elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        endian = ">"
    else:
        return []
    linktype = struct.unpack_from(endian + "I", data, 20)[0]
    off, names = 24, []
    while off + 16 <= len(data):
        try:
            _ts, _tu, incl, _orig = struct.unpack_from(endian + "IIII", data, off)
        except struct.error:
            break
        pkt = data[off + 16: off + 16 + incl]
        off += 16 + incl
        if linktype == 1 and len(pkt) > 14:
            ip = pkt[14:]
        elif linktype == 276 and len(pkt) > 20:
            ip = pkt[20:]
        elif linktype == 113 and len(pkt) > 16:
            ip = pkt[16:]
        else:
            continue
        if len(ip) < 20 or (ip[0] >> 4) != 4 or ip[9] != 17:
            continue
        ihl = (ip[0] & 0x0F) * 4
        l4 = ip[ihl:]
        if len(l4) < 8:
            continue
        sp, dp = struct.unpack_from(">HH", l4, 0)
        if 53 not in (sp, dp):
            continue
        payload = l4[8:]
        if len(payload) < 13:
            continue
        qd = struct.unpack_from(">H", payload, 4)[0]
        pos = 12
        for _ in range(min(qd, 4)):
            name, pos = _read_name(payload, pos)
            if name:
                names.append(name)
            pos += 4
    return names


def collect(names):
    """Сгруппировать метки по номеру и склеить в порядке номеров."""
    by_idx, plain = {}, []
    for name in names:
        for label in name.split("."):
            m = LABEL_RX.match(label)
            if not m:
                continue
            chunk = m.group(1)
            if len(chunk) < 8:
                continue
            prefix = label.split("-")[0]
            if prefix.isdigit():
                by_idx.setdefault(int(prefix), []).append(chunk)
            else:
                plain.append(chunk)
    ordered = [c for i in sorted(by_idx) for c in by_idx[i]] or plain
    return ordered


def try_decode(chunks):
    out = []
    joined = "".join(chunks)
    for kind, fn in (("b32", lambda s: base64.b32decode(
                         s.upper() + "=" * (-len(s.upper()) % 8))),
                     ("b64", lambda s: base64.b64decode(
                         s + "=" * (-len(s) % 4))),
                     ("hex", lambda s: bytes.fromhex(s))):
        try:
            raw = fn(joined)
        except Exception:
            continue
        if len(raw) < 6:
            continue
        printable = sum(32 <= b < 127 for b in raw) / len(raw)
        text = raw.decode("utf-8", "replace")
        m = re.search(r"[A-Za-z0-9_]{2,20}\{[ -~]{3,120}\}", text)
        out.append({"kind": kind, "printable": round(printable, 2),
                    "text": text[:400], "flag": m.group(0) if m else None})
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("file")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    data = open(args.file, "rb").read()
    names = dns_queries(data)
    chunks = collect(names)
    res = {"file": args.file, "labels": len(chunks), "decoded": try_decode(chunks)}
    if args.json:
        print(json.dumps(res, ensure_ascii=False))
        return 0
    print(f"[+] {args.file}: DNS-имён {len(names)}, меток-данных {len(chunks)}")
    flags = 0
    for d in res["decoded"]:
        print(f"    {d['kind']}: printable={d['printable']} {d['text'][:80]!r}")
        if d["flag"]:
            print(f"[!!!] ФЛАГ: {d['flag']}")
            flags += 1
    if not res["decoded"]:
        print("[-] ничего не декодировалось")
    return 0 if flags else 1


if __name__ == "__main__":
    raise SystemExit(main())
