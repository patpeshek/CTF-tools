#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
pcap_service.py — найти в pcap сервис задачи: имя, IP, порт, протокол.

  python pcap_service.py capture.pcap
  python pcap_service.py capture.pcap --json
  python pcap_service.py capture.pcap --probe          # один UDP/TCP пакет

Зачем: в сетевых задачах решение часто «найди в дампе сайт и порт, подключись
nc -u». Имя и порт обычно лежат в mDNS/DNS: SRV-запись `_nc._udp.<домен>`
даёт порт, A-запись — адрес. Инструмент вытаскивает это без внешних библиотек.

Поддерживаются pcap с Ethernet, Linux cooked (SLL/SLL2) и raw IP.
"""
from __future__ import annotations

try:
    import sys as _sys
    for _stream in (_sys.stdout, _sys.stderr):
        _stream.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

import argparse
import json
import re
import socket
import struct

SRV_HINT = re.compile(rb"_([a-z0-9-]+)_(udp|tcp)", re.I)


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


def _dns_records(msg: bytes):
    """[(kind, name, rtype, value)] из DNS/mDNS пакета."""
    out = []
    if len(msg) < 12:
        return out
    qd, an, ns, ar = struct.unpack_from(">HHHH", msg, 4)
    pos = 12
    try:
        for _ in range(qd):
            name, pos = _read_name(msg, pos)
            qtype, _qclass = struct.unpack_from(">HH", msg, pos)
            pos += 4
            out.append(("Q", name, qtype, None))
        for _ in range(an + ns + ar):
            name, pos = _read_name(msg, pos)
            rtype, _rclass, _ttl, rdlen = struct.unpack_from(">HHIH", msg, pos)
            pos += 10
            rdata = msg[pos:pos + rdlen]
            pos += rdlen
            val = None
            if rtype == 1 and rdlen == 4:
                val = ".".join(str(b) for b in rdata)
            elif rtype == 28 and rdlen == 16:
                val = socket.inet_ntop(socket.AF_INET6, rdata)
            elif rtype == 33 and rdlen >= 6:
                _prio, _w, port = struct.unpack_from(">HHH", rdata, 0)
                target, _ = _read_name(msg, pos - rdlen + 6)
                val = {"target": target, "port": port}
            elif rtype == 16:
                parts, i = [], 0
                while i < len(rdata):
                    ln = rdata[i]
                    parts.append(rdata[i + 1:i + 1 + ln].decode("latin-1", "replace"))
                    i += 1 + ln
                val = " | ".join(parts)
            elif rtype == 12:
                val = _read_name(msg, pos - rdlen)[0]
            if val is not None:
                out.append(("R", name, rtype, val))
    except (struct.error, IndexError):
        pass
    return out


def scan_pcap(path: str):
    data = open(path, "rb").read()
    magic = data[:4]
    if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        endian = "<"
    elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        endian = ">"
    else:
        raise SystemExit("[-] это не pcap (магия %r)" % magic)
    linktype = struct.unpack_from(endian + "I", data, 20)[0]
    off = 24
    services, dns_seen = [], {}
    while off + 16 <= len(data):
        try:
            _ts, _tu, incl, _orig = struct.unpack_from(endian + "IIII", data, off)
        except struct.error:
            break
        pkt = data[off + 16: off + 16 + incl]
        off += 16 + incl
        if linktype == 1 and len(pkt) > 14:
            proto, ip = struct.unpack_from(">H", pkt, 12)[0], pkt[14:]
        elif linktype == 276 and len(pkt) > 20:
            proto, ip = struct.unpack_from(">H", pkt, 0)[0], pkt[20:]
        elif linktype == 113 and len(pkt) > 16:
            proto, ip = struct.unpack_from(">H", pkt, 14)[0], pkt[16:]
        elif linktype == 101:
            proto, ip = 0x0800, pkt
        else:
            continue
        if proto != 0x0800 or len(ip) < 20 or (ip[0] >> 4) != 4:
            continue
        ihl = (ip[0] & 0x0F) * 4
        l4 = ip[ihl:]
        if ip[9] == 17 and len(l4) >= 8:
            sp, dp = struct.unpack_from(">HH", l4, 0)
            payload = l4[8:]
            if 53 in (sp, dp) or 5353 in (sp, dp):
                for kind, name, rtype, val in _dns_records(payload):
                    if kind == "R":
                        dns_seen.setdefault(name.lower(), []).append((rtype, val))
    # SRV даёт порт, A — адрес; складываем в сервис
    for name, recs in dns_seen.items():
        ports = [v["port"] for t, v in recs if t == 33 and isinstance(v, dict)]
        proto = "udp" if b"_udp" in name.encode().lower() else ("tcp" if "_tcp" in name.lower() else "?")
        if not ports:
            continue
        for t, v in recs:
            if t == 33 and isinstance(v, dict):
                target = v["target"]
                addrs = [vv for tt, vv in dns_seen.get(target.lower(), []) if tt == 1]
                services.append({"name": name, "host": target,
                                 "addr": addrs[0] if addrs else None,
                                 "port": v["port"], "proto": proto})
        for t, v in recs:
            if t == 16:
                services[-1].setdefault("txt", []).append(v)
    return services, dns_seen


def probe(service, timeout=3.0):
    host = service.get("addr") or service["host"]
    port = service["port"]
    try:
        if service["proto"] == "udp":
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(timeout)
                s.sendto(b"hello\n", (host, port))
                data, _ = s.recvfrom(4096)
                return data.decode("utf-8", "replace")
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            try:
                return s.recv(4096).decode("utf-8", "replace")
            except socket.timeout:
                return ""
    except OSError as exc:
        return f"ошибка: {exc}"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("file")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--probe", action="store_true",
                    help="отправить один пакет найденному сервису")
    args = ap.parse_args()
    services, dns_seen = scan_pcap(args.file)
    if args.json:
        print(json.dumps({"services": services,
                          "dns": {k: v for k, v in list(dns_seen.items())[:50]}},
                         ensure_ascii=False))
        return 0 if services else 1
    print(f"[+] {args.file}: DNS-имён {len(dns_seen)}, сервисов {len(services)}")
    for s in services:
        print(f"    {s['name']} -> {s['host']} ({s['addr'] or '?'}) "
              f"порт {s['port']}/{s['proto']}")
        if args.probe:
            print("      проверка:", repr(probe(s))[:120])
    if not services:
        print("[-] SRV-записи с портом не нашлись")
    return 0 if services else 1


if __name__ == "__main__":
    raise SystemExit(main())
