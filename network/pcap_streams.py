#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
pcap_streams.py — разбор PCAP/PCAPNG на чистом stdlib: DNS, UDP- и TCP-потоки,
реконструкция TCP по seq, HTTP-разбор, поиск флагов/доменов/base64/hex.

  python pcap_streams.py capture.pcap                 # сводка: пакеты, протоколы, топ
  python pcap_streams.py capture.pcap --dns           # DNS-запросы и ответы (имя -> IP)
  python pcap_streams.py capture.pcap --udp           # все UDP-потоки с payload
  python pcap_streams.py capture.pcap --tcp           # TCP-потоки, HTTP-запросы/ответы
  python pcap_streams.py capture.pcap --all           # dns + udp + tcp + findings
  python pcap_streams.py capture.pcap --json out.json # всё в машиночитаемом виде
  python pcap_streams.py capture.pcap --grep flag     # искать подстроку в любом payload
  python pcap_streams.py capture.pcap --udp --hex     # payload как hex
  python pcap_streams.py capture.pcap --all --limit 20  # то же, но не всё подряд

Читает libpcap (d4c3b2a1 / a1b2c3d4, в т.ч. наносекундные 4d3cb2a1 / a1b23c4d)
и pcapng (SHB/IDB/EPB/SPB), gzip тоже понимает. Канальный уровень: Ethernet
(с VLAN), Linux SLL и SLL2, RAW IP, NULL/loopback. IPv4 с опциями и сборкой
фрагментов, IPv6 с цепочкой заголовков расширений. TCP склеивается по seq
(ретрансмиты, переполнение 32 бит, дыры), HTTP разбирается вместе с chunked,
TLS-потоки опознаются по SNI. Сети не трогает — только читает файл.
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
import gzip
import ipaddress
import json
import os
import re
import socket
import struct
from collections import Counter

# ---------------------------------------------------------------- константы --

MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", 1e-6),   # классический, little-endian, мкс
    b"\xa1\xb2\xc3\xd4": (">", 1e-6),
    b"\x4d\x3c\xb2\xa1": ("<", 1e-9),   # наносекундный
    b"\xa1\xb2\x3c\x4d": (">", 1e-9),
}

# Канальные уровни, которые умеем разбирать.
LINK_ETHERNET, LINK_RAW, LINK_LOOP, LINK_SLL, LINK_SLL2 = 1, 101, 108, 113, 276

# Номера протоколов IP.
IP_TCP, IP_UDP, IP_ICMP, IP_ICMP6 = 6, 17, 1, 58

TCP_FLAGS = ((0x100, "NS"), (0x080, "CWR"), (0x040, "ECE"), (0x020, "URG"),
             (0x010, "ACK"), (0x008, "PSH"), (0x004, "RST"), (0x002, "SYN"),
             (0x001, "FIN"))

DNS_TYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX",
             16: "TXT", 28: "AAAA", 33: "SRV", 41: "OPT", 65: "HTTPS",
             255: "ANY"}

HTTP_METHODS = (b"GET ", b"POST ", b"PUT ", b"HEAD ", b"DELETE ",
                b"OPTIONS ", b"PATCH ", b"TRACE ", b"CONNECT ")

# Только печатаемые символы и осмысленный префикс (3+ символа), иначе случайные
# байты в шифрованном TLS дают тысячи ложных "xxx{...}".
FLAG_RE = re.compile(rb"(?<![A-Za-z0-9_])[A-Za-z][A-Za-z0-9_]{2,20}\{[\x20-\x7e]{1,200}\}")
DOMAIN_RE = re.compile(rb"(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
                       rb"(?:com|net|org|ru|io|dev|xyz|local|lan|internal|test|"
                       rb"onion|su|info|site|online|app|cloud|tech|me|cc|top|"
                       rb"edu|gov|biz|pro|shop|store|link|space|live|fun|club)\b")
# Уверенный флаг: префикс — известное ключевое слово.
FLAG_KW_RE = re.compile(rb"(?i)(?<![A-Za-z0-9_])(?:flag|ctf|key|secret|token|"
                        rb"answer|pass(?:word)?|codeword)\{[\x20-\x7e]{1,200}\}")
B64_RE = re.compile(rb"[A-Za-z0-9+/]{20,}={0,2}")
HEX_RE = re.compile(rb"\b(?:[0-9a-fA-F]{2}[\s:]){15,}[0-9a-fA-F]{2}\b")


# -------------------------------------------------------------- чтецы файла --

def _open_bytes(path):
    """Открыть pcap, понимая gzip. Возвращает (bytes, имя)."""
    with open(path, "rb") as fh:
        head = fh.read(4)
        if head[:2] == b"\x1f\x8b":
            with gzip.open(path, "rb") as gz:
                return gz.read(), path
        rest = fh.read()
    return head + rest, path


def read_pcap(path):
    """Генератор (ts, linktype, frame) для libpcap и pcapng."""
    data, _ = _open_bytes(path)
    if len(data) < 24:
        raise ValueError("файл короче заголовка pcap")
    magic = data[:4]
    if magic in MAGICS:
        yield from _read_classic(data, magic)
    elif magic == b"\x0a\x0d\x0d\x0a":
        yield from _read_pcapng(data)
    else:
        raise ValueError("неизвестная сигнатура: %s" % magic.hex())


def _read_classic(data, magic):
    endian, mul = MAGICS[magic]
    ver_maj, ver_min, _, _, snap, linktype = struct.unpack(endian + "HHiIII", data[4:24])
    off = 24
    n = len(data)
    hdr = struct.Struct(endian + "IIII")
    while off + 16 <= n:
        ts_s, ts_f, incl, _orig = hdr.unpack_from(data, off)
        off += 16
        if incl > n - off:          # битый/обрезанный файл
            incl = n - off
        yield ts_s + ts_f * mul, linktype, data[off:off + incl]
        off += incl


def _read_pcapng(data):
    off = 0
    n = len(data)
    endian = "<"
    ifaces = []          # список linktype по ID
    while off + 12 <= n:
        btype = struct.unpack_from(endian + "I", data, off)[0] if endian else 0
        if data[off:off + 4] == b"\x0a\x0d\x0d\x0a":
            # SHB: определяем порядок байт по полю BOM на offset 8
            bom = data[off + 8:off + 12]
            endian = "<" if bom == b"\x4d\x3c\x2b\x1a" else ">"
            btype = 0x0A0D0D0A
        blen = struct.unpack_from(endian + "I", data, off + 4)[0]
        if blen < 12 or off + blen > n:
            break
        body = data[off + 8:off + blen - 4]
        if btype == 0x00000001 and len(body) >= 8:          # IDB
            ifaces.append(struct.unpack_from(endian + "H", body, 0)[0])
        elif btype == 0x00000006 and len(body) >= 20:       # EPB
            ifid, ts_hi, ts_lo, cap, _orig = struct.unpack_from(endian + "IIIII", body, 0)
            link = ifaces[ifid] if ifid < len(ifaces) else LINK_ETHERNET
            yield (ts_hi << 32 | ts_lo) / 1e6, link, body[20:20 + cap]
        elif btype == 0x00000003 and len(body) >= 4:        # SPB
            orig = struct.unpack_from(endian + "I", body, 0)[0]
            link = ifaces[0] if ifaces else LINK_ETHERNET
            yield 0.0, link, body[4:4 + orig]
        elif btype == 0x00000002 and len(body) >= 20:       # старый Packet Block
            ifid, _drops, ts_hi, ts_lo, cap, _orig = struct.unpack_from(endian + "HHIIII", body, 0)
            link = ifaces[ifid] if ifid < len(ifaces) else LINK_ETHERNET
            yield (ts_hi << 32 | ts_lo) / 1e6, link, body[20:20 + cap]
        off += blen


# ------------------------------------------------------------ разбор кадров --

def strip_link(frame, linktype):
    """Снять канальный заголовок. Возвращает (ethertype, offset) или (None, 0)."""
    if linktype == LINK_ETHERNET:
        if len(frame) < 14:
            return None, 0
        et = struct.unpack_from(">H", frame, 12)[0]
        off = 14
        while et in (0x8100, 0x88A8, 0x9100) and len(frame) >= off + 4:  # VLAN
            et = struct.unpack_from(">H", frame, off + 2)[0]
            off += 4
        return et, off
    if linktype == LINK_SLL:            # 16 байт: pkttype, hatype, halen, addr8, proto
        if len(frame) < 16:
            return None, 0
        return struct.unpack_from(">H", frame, 14)[0], 16
    if linktype == LINK_SLL2:           # 20 байт: proto, reserved, ifindex, hatype, pkttype, halen, addr8
        if len(frame) < 20:
            return None, 0
        return struct.unpack_from(">H", frame, 0)[0], 20
    if linktype in (LINK_RAW, LINK_LOOP):
        if not frame:
            return None, 0
        ver = frame[0] >> 4
        if linktype == LINK_LOOP and len(frame) >= 4:   # 4 байта семейства адресов
            return (0x0800 if ver == 4 else 0x86DD), 4
        return (0x0800 if ver == 4 else 0x86DD), 0
    return None, 0


def parse_ipv4(data, off):
    """IPv4-заголовок. Возвращает dict или None."""
    if len(data) < off + 20:
        return None
    vihl = data[off]
    if vihl >> 4 != 4:
        return None
    ihl = (vihl & 0x0F) * 4
    if ihl < 20 or len(data) < off + ihl:
        return None
    tot = struct.unpack_from(">H", data, off + 2)[0]
    ident, frag = struct.unpack_from(">HH", data, off + 4)
    ttl, proto = data[off + 8], data[off + 9]
    src = socket.inet_ntoa(data[off + 12:off + 16])
    dst = socket.inet_ntoa(data[off + 16:off + 20])
    payload = data[off + ihl:off + (tot if ihl <= tot <= len(data) - off else len(data) - off)]
    return {
        "v": 4, "src": src, "dst": dst, "proto": proto, "ttl": ttl,
        "id": ident, "mf": bool(frag & 0x2000), "fragoff": (frag & 0x1FFF) * 8,
        "payload": payload,
    }


def parse_ipv6(data, off):
    """IPv6 с обходом заголовков расширений (hop-by-hop, routing, frag, dst opts)."""
    if len(data) < off + 40:
        return None
    if data[off] >> 4 != 6:
        return None
    plen = struct.unpack_from(">H", data, off + 4)[0]
    nxt, hop = data[off + 6], data[off + 7]
    src = ipaddress.IPv6Address(data[off + 8:off + 24]).compressed
    dst = ipaddress.IPv6Address(data[off + 24:off + 40]).compressed
    pos = off + 40
    end = min(off + 40 + plen, len(data))
    frag_off = 0
    while nxt in (0, 43, 44, 51, 60) and pos + 2 <= end:
        if nxt == 44:                       # Fragment header
            fo = struct.unpack_from(">H", data, pos + 2)[0]
            frag_off = fo & 0xFFF8
            nxt = data[pos]
            pos += 8
            continue
        hlen = (data[pos + 1] + 1) * 8
        nxt = data[pos]
        pos += hlen
    return {
        "v": 6, "src": src, "dst": dst, "proto": nxt, "ttl": hop,
        "id": 0, "mf": False, "fragoff": frag_off,
        "payload": data[pos:end],
    }


def _l4_ports(payload):
    if len(payload) < 4:
        return None
    return struct.unpack_from(">HH", payload, 0)


def _tcp_flags(seg):
    """Флаги TCP по смещению 12..14 (включая NS)."""
    if len(seg) < 14:
        return ""
    bits = ((seg[12] & 0x01) << 8) | seg[13]
    return ",".join(name for mask, name in TCP_FLAGS if bits & mask) or "-"


def _tcp_hdr_len(seg):
    if len(seg) < 13:
        return 0
    return (seg[12] >> 4) * 4


# ------------------------------------------------------------------- DNS ----

def _dns_name(data, pos):
    """Читает DNS-имя с учётом указателей сжатия. -> (name, next_pos)."""
    labels = []
    end = pos
    jumped = False
    hops = 0
    while True:
        if pos >= len(data):
            return None, end
        ln = data[pos]
        if ln == 0:
            pos += 1
            if not jumped:
                end = pos
            break
        if ln & 0xC0 == 0xC0:
            if pos + 1 >= len(data):
                return None, end
            ptr = ((ln & 0x3F) << 8) | data[pos + 1]
            if not jumped:
                end = pos + 2
            pos = ptr
            jumped = True
            hops += 1
            if hops > 64 or ptr >= len(data):
                return None, end
            continue
        if ln & 0xC0:                       # зарезервированные биты
            return None, end
        pos += 1
        if pos + ln > len(data):
            return None, end
        labels.append(data[pos:pos + ln].decode("latin-1"))
        pos += ln
        if not jumped:
            end = pos
    return ".".join(labels), end


def _dns_rdata(data, pos, rdlen, rtype):
    """Декодирует RDATA, начиная с абсолютной позиции pos."""
    raw = data[pos:pos + rdlen]
    try:
        if rtype == 1 and rdlen == 4:
            return socket.inet_ntoa(raw)
        if rtype == 28 and rdlen == 16:
            return ipaddress.IPv6Address(raw).compressed
        if rtype in (2, 5, 12):
            name, _ = _dns_name(data, pos)
            return name
        if rtype == 15:                     # MX: preference + name
            pref = struct.unpack_from(">H", raw, 0)[0] if len(raw) >= 2 else 0
            name, _ = _dns_name(data, pos + 2)
            return "%d %s" % (pref, name)
        if rtype == 16:                     # TXT: length-prefixed строки
            out, i = [], 0
            while i < len(raw):
                ln = raw[i]
                out.append(raw[i + 1:i + 1 + ln].decode("latin-1"))
                i += 1 + ln
            return " | ".join(out)
        if rtype == 6:                      # SOA
            mname, p = _dns_name(data, pos)
            rname, p = _dns_name(data, p)
            return "%s %s" % (mname, rname)
        if rtype == 33 and len(raw) >= 6:   # SRV
            prio, weight, port = struct.unpack_from(">HHH", raw, 0)
            target, _ = _dns_name(data, pos + 6)
            return "%d %d %d %s" % (prio, weight, port, target)
    except Exception:
        pass
    return raw.hex()


def parse_dns(data):
    """Разбирает DNS-сообщение. -> dict или None."""
    if len(data) < 12:
        return None
    tid, flags, qd, an, ns, ar = struct.unpack_from(">HHHHHH", data, 0)
    qr = (flags >> 15) & 1
    opcode = (flags >> 11) & 0xF
    rcode = flags & 0xF
    # отсекаем мусор: слишком много записей для короткого пакета
    if qd > 64 or an > 256 or ns > 256 or ar > 256:
        return None
    pos = 12
    questions = []
    for _ in range(qd):
        name, pos = _dns_name(data, pos)
        if name is None or pos + 4 > len(data):
            return None
        qtype, qclass = struct.unpack_from(">HH", data, pos)
        pos += 4
        questions.append({"name": name, "type": DNS_TYPES.get(qtype, str(qtype)),
                          "class": qclass})
    answers = []
    for _ in range(an + ns + ar):
        name, pos = _dns_name(data, pos)
        if name is None or pos + 10 > len(data):
            break
        rtype, rclass, ttl, rdlen = struct.unpack_from(">HHIH", data, pos)
        pos += 10
        if pos + rdlen > len(data):
            break
        answers.append({"name": name, "type": DNS_TYPES.get(rtype, str(rtype)),
                        "ttl": ttl, "value": _dns_rdata(data, pos, rdlen, rtype)})
        pos += rdlen
    return {"id": tid, "qr": qr, "opcode": opcode, "rcode": rcode,
            "questions": questions, "answers": answers}


# ------------------------------------------------------------ HTTP-разбор ---

def _headers_from(head: bytes):
    hdrs = {}
    for line in head.split(b"\r\n")[1:]:
        if b":" in line:
            k, v = line.split(b":", 1)
            hdrs[k.strip().lower().decode("latin-1")] = v.strip().decode("latin-1", "replace")
    return hdrs


def parse_http(data: bytes):
    """Разбирает пачку HTTP-сообщений в реконструированном потоке."""
    items = []
    i = 0
    n = len(data)
    while i < n:
        starts = [data.find(m, i) for m in HTTP_METHODS]
        starts = [p for p in starts if p >= 0]
        hpos = data.find(b"HTTP/", i)
        if hpos >= 0:
            starts.append(hpos)
        if not starts:
            break
        start = min(starts)
        hdr_end = data.find(b"\r\n\r\n", start)
        if hdr_end < 0:
            break
        head = data[start:hdr_end]
        hdrs = _headers_from(head)
        first = head.split(b"\r\n", 1)[0].decode("latin-1", "replace")
        kind = "request" if first.split(" ")[0] in (
            m.decode().strip() for m in HTTP_METHODS) else "response"
        body_start = hdr_end + 4
        length = hdrs.get("content-length", "")
        body = b""
        if length.isdigit():
            body = data[body_start:body_start + int(length)]
            next_i = body_start + int(length)
        elif hdrs.get("transfer-encoding", "").lower() == "chunked":
            body, next_i = _dechunk(data, body_start)
        else:
            next_i = body_start
        items.append({"kind": kind, "first_line": first, "headers": hdrs,
                      "body_len": len(body), "body": body})
        i = max(next_i, start + 1)
    return items


def tls_sni(data):
    """Достаёт SNI из TLS ClientHello (по началу потока). -> str|None."""
    if len(data) < 43 or data[0] != 0x16 or data[5] != 0x01:
        return None
    try:
        pos = 9 + 2 + 32                     # handshake hdr + version + random
        sid_len = data[pos]
        pos += 1 + sid_len
        cs_len = struct.unpack_from(">H", data, pos)[0]
        pos += 2 + cs_len
        comp_len = data[pos]
        pos += 1 + comp_len
        if pos + 2 > len(data):
            return None
        ext_total = struct.unpack_from(">H", data, pos)[0]
        pos += 2
        end = min(pos + ext_total, len(data))
        while pos + 4 <= end:
            etype, elen = struct.unpack_from(">HH", data, pos)
            pos += 4
            if etype == 0:                   # server_name
                npos = pos + 2               # список: длина(2)
                while npos + 3 <= pos + elen:
                    ntype = data[npos]
                    nlen = struct.unpack_from(">H", data, npos + 1)[0]
                    name = data[npos + 3:npos + 3 + nlen]
                    if ntype == 0 and name:
                        return name.decode("latin-1")
                    npos += 3 + nlen
            pos += elen
    except Exception:
        return None
    return None


def _dechunk(data, pos):
    """Распаковка chunked. -> (body, next_pos)."""
    out = bytearray()
    n = len(data)
    while pos < n:
        eol = data.find(b"\r\n", pos)
        if eol < 0:
            break
        try:
            size = int(data[pos:eol].split(b";")[0], 16)
        except ValueError:
            break
        pos = eol + 2
        if size == 0:
            end = data.find(b"\r\n", pos)
            pos = end + 2 if end >= 0 else n
            break
        out += data[pos:pos + size]
        pos += size + 2
    return bytes(out), pos


# --------------------------------------------------------- потоки и сборка --

class TcpStream:
    """Одно направление TCP: сегменты -> сплошной буфер по seq."""

    def __init__(self):
        self.segs = []       # (seq, bytes, ts)
        self.syn_seq = None
        self.fin = False
        self.rst = False

    def add(self, seq, payload, ts, flags):
        if "SYN" in flags and self.syn_seq is None:
            self.syn_seq = seq
        if payload:
            self.segs.append((seq, payload, ts))
        if "FIN" in flags:
            self.fin = True
        if "RST" in flags:
            self.rst = True

    def rebuild(self):
        """Склеивает по seq с учётом переполнения 32 бит и дыр."""
        if not self.segs:
            return b"", []
        base = min(s for s, _, _ in self.segs)
        end = max(s + len(d) for s, d, _ in self.segs)
        if end - base > 64 * 1024 * 1024:      # защита от мусора
            return b"", []
        buf = bytearray(end - base)
        filled = bytearray(end - base)
        for seq, d, _ in sorted(self.segs):
            o = seq - base
            if o < 0:                               # обёртка seq через 2**32
                o += 1 << 32
                if o > len(buf):
                    continue
            buf[o:o + len(d)] = d
            filled[o:o + len(d)] = b"\x01" * len(d)
        gaps = []
        run = None
        for idx, f in enumerate(filled):
            if not f and run is None:
                run = idx
            elif f and run is not None:
                gaps.append((run, idx))
                run = None
        if run is not None:
            gaps.append((run, len(filled)))
        return bytes(buf), gaps


def collect(path):
    """Главный проход по файлу: пакеты, DNS, UDP-датаграммы, TCP-сегменты."""
    stats = Counter()
    conversations = Counter()
    linktypes = Counter()
    dns = []
    udp_datagrams = []                 # (ts, src, sport, dst, dport, payload)
    tcp_segments = []                  # (ts, src, sport, dst, dport, seq, payload, flags)
    frags = {}                         # (src, dst, id, proto) -> {off: bytes}
    icmp_payloads = []
    other = Counter()
    first_ts = last_ts = None

    for ts, linktype, frame in read_pcap(path):
        if first_ts is None:
            first_ts = ts
        last_ts = ts
        linktypes[linktype] += 1
        stats["packets"] += 1
        stats["bytes"] += len(frame)

        et, off = strip_link(frame, linktype)
        if et is None:
            stats["bad_frame"] += 1
            continue
        ip = None
        if et == 0x0800 or et == 0x0000:
            ip = parse_ipv4(frame, off)
        elif et == 0x86DD:
            ip = parse_ipv6(frame, off)
        else:
            other["ethertype_%04x" % et] += 1
            continue
        if ip is None:
            stats["bad_ip"] += 1
            continue
        stats["ipv%d" % ip["v"]] += 1

        payload = ip["payload"]
        if ip["v"] == 4 and (ip["mf"] or ip["fragoff"]):
            key = (ip["src"], ip["dst"], ip["id"], ip["proto"])
            slot = frags.setdefault(key, {"parts": {}, "total": None, "ts": ts})
            slot["parts"][ip["fragoff"]] = payload
            if not ip["mf"]:
                slot["total"] = ip["fragoff"] + len(payload)
            stats["fragments"] += 1
            total = slot["total"]
            if total is None:
                continue                    # ждём последний фрагмент
            # проверяем, что интервалы покрывают [0, total) без дыр
            filled = 0
            for off in sorted(slot["parts"]):
                if off > filled:
                    break
                filled = max(filled, off + len(slot["parts"][off]))
            if filled < total:
                continue                    # ещё не всё пришло
            joined = bytearray(total)
            for off, d in slot["parts"].items():
                joined[off:off + len(d)] = d
            payload = bytes(joined)
            stats["defragmented"] += 1
            del frags[key]

        proto = ip["proto"]
        conversations[(ip["src"], ip["dst"])] += 1

        if proto == IP_TCP:
            ports = _l4_ports(payload)
            if not ports:
                continue
            sport, dport = ports
            hlen = _tcp_hdr_len(payload)
            if hlen < 20 or hlen > len(payload):
                stats["bad_tcp"] += 1
                continue
            seq = struct.unpack_from(">I", payload, 4)[0]
            flags = _tcp_flags(payload)
            stats["tcp"] += 1
            tcp_segments.append((ts, ip["src"], sport, ip["dst"], dport, seq,
                                 payload[hlen:], flags))
        elif proto == IP_UDP:
            ports = _l4_ports(payload)
            if not ports:
                continue
            sport, dport = ports
            data = payload[8:]
            stats["udp"] += 1
            if len(data) >= 12:
                msg = parse_dns(data)
                if msg is not None:
                    msg["ts"] = ts
                    msg["src"] = ip["src"]
                    msg["dst"] = ip["dst"]
                    msg["sport"] = sport
                    msg["dport"] = dport
                    msg["raw"] = data
                    dns.append(msg)
                    stats["dns"] += 1
            udp_datagrams.append((ts, ip["src"], sport, ip["dst"], dport, data))
        elif proto in (IP_ICMP, IP_ICMP6):
            stats["icmp"] += 1
            if len(payload) > 8:
                icmp_payloads.append((ts, ip["src"], ip["dst"], payload[8:]))
        else:
            stats["ip_other"] += 1

    return {
        "stats": stats, "conversations": conversations, "linktypes": linktypes,
        "dns": dns, "udp": udp_datagrams, "tcp": tcp_segments,
        "icmp": icmp_payloads, "other": other,
        "first_ts": first_ts, "last_ts": last_ts,
    }


def build_udp_flows(datagrams):
    """Группирует датаграммы в потоки по 5-tuple (направление сохраняется)."""
    flows = {}
    order = []
    for ts, src, sport, dst, dport, data in datagrams:
        key = (src, sport, dst, dport)
        if key not in flows:
            flows[key] = {"first_ts": ts, "last_ts": ts, "count": 0,
                          "bytes": 0, "dgrams": []}
            order.append(key)
        f = flows[key]
        f["count"] += 1
        f["bytes"] += len(data)
        f["first_ts"] = min(f["first_ts"], ts)
        f["last_ts"] = max(f["last_ts"], ts)
        f["dgrams"].append((ts, data))
    return [(k, flows[k]) for k in order]


def build_tcp_flows(segments):
    """Склеивает TCP по направлениям и попарно (клиент->сервер / обратно)."""
    dirs = {}
    order = []
    meta = {}
    for ts, src, sport, dst, dport, seq, payload, flags in segments:
        key = (src, sport, dst, dport)
        if key not in dirs:
            dirs[key] = TcpStream()
            order.append(key)
            meta[key] = {"first_ts": ts, "last_ts": ts, "packets": 0, "bytes": 0}
        dirs[key].add(seq, payload, ts, flags)
        meta[key]["last_ts"] = ts
        meta[key]["packets"] += 1
        meta[key]["bytes"] += len(payload)

    out = []
    seen = set()
    for key in order:
        if key in seen:
            continue
        src, sport, dst, dport = key
        rev = (dst, dport, src, sport)
        seen.add(key)
        seen.add(rev)
        a, b = dirs[key], dirs.get(rev)
        da, ga = a.rebuild()
        db, gb = (b.rebuild() if b else (b"", []))
        # клиент — тот, кто прислал SYN; иначе сторона с большим портом
        client_is_a = True
        if b is not None and b.syn_seq is not None and a.syn_seq is None:
            client_is_a = False
        elif a.syn_seq is None and (b is None or b.syn_seq is None):
            client_is_a = sport > dport
        if client_is_a:
            client, server = (src, sport), (dst, dport)
            c2s, s2c, g_c2s, g_s2c = da, db, ga, gb
            p_c2s = meta[key]["packets"]
            p_s2c = meta[rev]["packets"] if rev in meta else 0
        else:
            client, server = (dst, dport), (src, sport)
            c2s, s2c, g_c2s, g_s2c = db, da, gb, ga
            p_c2s = meta[rev]["packets"] if rev in meta else 0
            p_s2c = meta[key]["packets"]
        out.append({
            "client": client, "server": server,
            "c2s": c2s, "s2c": s2c,
            "len_c2s": len(c2s), "len_s2c": len(s2c),
            "gaps_c2s": g_c2s, "gaps_s2c": g_s2c,
            "packets_c2s": p_c2s, "packets_s2c": p_s2c,
            "syn": a.syn_seq is not None or (b is not None and b.syn_seq is not None),
            "fin": a.fin or (b is not None and b.fin),
            "rst": a.rst or (b is not None and b.rst),
            "sni": tls_sni(c2s),
            "first_ts": meta[key]["first_ts"],
            "last_ts": meta[key]["last_ts"],
        })
    return out


# -------------------------------------------------------------- отображение --

def is_text(data, threshold=0.85):
    """Похоже ли на текст (печатаемый ASCII + переводы строк)."""
    if not data:
        return False
    good = sum(1 for b in data if 32 <= b < 127 or b in (9, 10, 13))
    return good / len(data) >= threshold


def preview(data, limit=300):
    """Текст, если похоже на текст, иначе hex."""
    if not data:
        return ""
    chunk = data[:limit]
    if is_text(chunk):
        text = chunk.decode("utf-8", "replace")
        text = "".join(ch if ch.isprintable() or ch in "\r\n\t" else "." for ch in text)
        return text + ("… (+%d b)" % (len(data) - limit) if len(data) > limit else "")
    hexed = chunk.hex()
    pretty = " ".join(hexed[i:i + 2] for i in range(0, len(hexed), 2))
    return "[hex] " + pretty + (" … (+%d b)" % (len(data) - limit) if len(data) > limit else "")


def fmt_ts(ts):
    if not ts:
        return "?"
    return "%.6f" % ts


def scan_findings(chunks):
    """Ищет флаги, домены, base64 и hex-строки в наборе (описание, bytes).

    Флаги делятся на уверенные (префикс — известное ключевое слово вроде flag/ctf)
    и слабые (любой word{...}), чтобы CSS вида html{...} не выглядел флагом.
    """
    strong, weak, domains, b64, hexstr = {}, {}, Counter(), Counter(), Counter()
    for where, data in chunks:
        for m in FLAG_KW_RE.finditer(data):
            strong.setdefault(m.group().decode("utf-8", "replace"), where)
        for m in FLAG_RE.finditer(data):
            tok = m.group().decode("utf-8", "replace")
            if tok in strong:
                continue
            body = tok.split("{", 1)[1]
            if ":" in body and ";" in body:      # CSS/JS-подобное, не флаг
                continue
            weak.setdefault(tok, where)
        for m in DOMAIN_RE.finditer(data):
            domains[m.group().decode("latin-1")] += 1
        for m in B64_RE.finditer(data):
            tok = m.group()
            if len(tok) >= 24:
                b64[tok] += 1
        for m in HEX_RE.finditer(data):
            hexstr[m.group()[:64]] += 1
    return strong, weak, domains, b64, hexstr


def all_payload_chunks(collected, udp_flows, tcp_flows):
    """Все payload'ы с человекочитаемым описанием источника."""
    for msg in collected["dns"]:
        yield ("dns %s:%d->%s:%d" % (msg["src"], msg["sport"], msg["dst"], msg["dport"]),
               msg.get("raw", b""))
    for (src, sport, dst, dport), f in udp_flows:
        for i, (ts, data) in enumerate(f["dgrams"], 1):
            yield ("udp %s:%d->%s:%d #%d" % (src, sport, dst, dport, i), data)
    for fl in tcp_flows:
        (src, sport), (dst, dport) = fl["client"], fl["server"]
        yield ("tcp %s:%d->%s:%d" % (src, sport, dst, dport), fl["c2s"])
        yield ("tcp %s:%d->%s:%d" % (dst, dport, src, sport), fl["s2c"])
    for ts, src, dst, data in collected["icmp"]:
        yield ("icmp %s->%s" % (src, dst), data)


# ------------------------------------------------------------------- вывод --

def show_summary(collected, udp_flows, tcp_flows):
    st = collected["stats"]
    print("=== Сводка ===")
    print("  пакетов: %d, байт: %d" % (st["packets"], st["bytes"]))
    print("  время: %s -> %s (%.2f c)" % (
        fmt_ts(collected["first_ts"]), fmt_ts(collected["last_ts"]),
        (collected["last_ts"] or 0) - (collected["first_ts"] or 0)))
    print("  канальный уровень: %s" % dict(collected["linktypes"]))
    depth = {k: st[k] for k in ("ipv4", "ipv6", "tcp", "udp", "dns", "icmp",
                                "fragments", "ip_other", "bad_frame") if st[k]}
    print("  протоколы: %s" % depth)

    # сводка по портам
    up = Counter()
    for (src, sport, dst, dport), f in udp_flows:
        up[dport] += f["count"]
        up[sport] += f["count"]
    tcp_ports = Counter()
    for fl in tcp_flows:
        tcp_ports[fl["server"][1]] += fl["packets_c2s"]
    if up:
        top = [(p, n) for p, n in up.most_common(14) if n >= 3]
        print("  UDP-порты (dst+src, >=3 датаграмм): %s" % dict(top))
    if tcp_ports:
        print("  TCP-порты сервера: %s" % dict(tcp_ports.most_common(10)))

    if collected["other"]:
        print("  прочие ethertype: %s" % dict(collected["other"]))
    print("\n  топ разговоров:")
    for (a, b), n in collected["conversations"].most_common(12):
        print("    %-40s -> %-40s %d" % (a, b, n))

    print("\n  потоки: UDP %d, TCP %d, DNS-сообщений %d" % (
        len(udp_flows), len(tcp_flows), len(collected["dns"])))
    big_udp = sorted(((f["bytes"], k) for k, f in udp_flows), reverse=True)[:5]
    if big_udp:
        print("  крупнейшие UDP-потоки:")
        for nbytes, (src, sport, dst, dport) in big_udp:
            print("    %s:%d -> %s:%d  %d b" % (src, sport, dst, dport, nbytes))


def show_dns(collected, limit=0):
    msgs = collected["dns"]
    print("=== DNS: %d сообщений ===" % len(msgs))
    pairs = {}
    shown = msgs if not limit else msgs[:limit]
    for m in shown:
        head = "  [%s] %s:%d -> %s:%d  id=0x%04x %s" % (
            "resp" if m["qr"] else "query", m["src"], m["sport"],
            m["dst"], m["dport"], m["id"], "" if not m["qr"] else
            "rcode=%d" % m["rcode"])
        qs = ", ".join("%s/%s" % (q["name"], q["type"]) for q in m["questions"]) or "(нет вопроса)"
        print(head)
        print("      Q: %s" % qs)
        for a in m["answers"]:
            if a["type"] == "OPT":
                continue
            print("      A: %-45s %-6s %s (ttl %s)" % (a["name"], a["type"],
                                                      a["value"], a["ttl"]))
            if a["type"] in ("A", "AAAA", "CNAME"):
                for q in m["questions"]:
                    pairs.setdefault(q["name"], set()).add(a["value"])
    if pairs:
        print("\n  имя -> адрес:")
        for name, vals in pairs.items():
            print("    %-45s %s" % (name, ", ".join(sorted(vals))))
    if limit and len(msgs) > limit:
        print("\n  … показано %d из %d (--limit)" % (limit, len(msgs)))


def show_udp(udp_flows, hexdump=False, max_dgrams=0, max_payload=300, limit=0):
    print("=== UDP-потоки: %d ===" % len(udp_flows))
    shown_flows = udp_flows if not limit else udp_flows[:limit]
    for (src, sport, dst, dport), f in shown_flows:
        print("\n  %s:%d -> %s:%d   %d датаграмм, %d b, %.3f c" % (
            src, sport, dst, dport, f["count"], f["bytes"],
            f["last_ts"] - f["first_ts"]))
        shown = f["dgrams"] if not max_dgrams else f["dgrams"][:max_dgrams]
        for i, (ts, data) in enumerate(shown, 1):
            body = data.hex() if hexdump else preview(data, max_payload)
            print("    #%-3d %s len=%-5d %s" % (i, fmt_ts(ts), len(data), body))
        if max_dgrams and len(f["dgrams"]) > max_dgrams:
            print("    … ещё %d датаграмм" % (len(f["dgrams"]) - max_dgrams))
    if limit and len(udp_flows) > limit:
        print("\n  … показано %d из %d потоков (--limit)" % (limit, len(udp_flows)))


def show_tcp(tcp_flows, max_payload=400, limit=0):
    print("=== TCP-потоки: %d ===" % len(tcp_flows))
    shown_flows = tcp_flows if not limit else tcp_flows[:limit]
    for fl in shown_flows:
        (cs, cp), (ss, sp) = fl["client"], fl["server"]
        marks = "".join(x for x, on in (("S", fl["syn"]), ("F", fl["fin"]),
                                        ("R", fl["rst"])) if on)
        print("\n  %s:%d <-> %s:%d   %d/%d пакетов, %d/%d b %s" % (
            cs, cp, ss, sp, fl["packets_c2s"], fl["packets_s2c"],
            fl["len_c2s"], fl["len_s2c"], ("[" + marks + "]") if marks else ""))
        if fl["sni"]:
            print("    TLS SNI: %s" % fl["sni"])
        if fl["gaps_c2s"] or fl["gaps_s2c"]:
            print("    дыры в seq: c2s=%s s2c=%s" % (fl["gaps_c2s"][:5],
                                                    fl["gaps_s2c"][:5]))

        for label, data in (("->", fl["c2s"]), ("<-", fl["s2c"])):
            if not data:
                continue
            items = parse_http(data)
            if items:
                for it in items:
                    print("    %s [%s] %s" % (label, it["kind"], it["first_line"][:160]))
                    for h in ("host", "user-agent", "content-type", "content-length",
                              "server", "location", "authorization", "cookie"):
                        if h in it["headers"]:
                            print("        %-14s %s" % (h + ":", it["headers"][h][:200]))
                    if it["body_len"]:
                        print("        body %d b: %s" % (
                            it["body_len"], preview(it["body"], max_payload)))
            else:
                print("    %s %d b: %s" % (label, len(data), preview(data, max_payload)))


def show_findings(collected, udp_flows, tcp_flows, grep=None, full=True):
    chunks = list(all_payload_chunks(collected, udp_flows, tcp_flows))
    strong, weak, domains, b64, hexstr = scan_findings(chunks)
    if full:
        print("=== Поиск ===")
        if strong:
            print("  [!!!] флаг по ключевому слову:")
            for val, where in strong.items():
                print("    %s   (%s)" % (val, where))
        else:
            print("  флагоподобных строк по ключевым словам нет")
        if weak:
            print("  прочие word{...} (низкая уверенность): %d" % len(weak))
            for val, where in list(weak.items())[:5]:
                print("    %s   (%s)" % (val[:120], where))

        if domains:
            print("\n  домены в payload: %s" % ", ".join(
                "%s x%d" % (d, n) for d, n in domains.most_common(20)))
        if b64:
            print("\n  base64-кандидаты:")
            for tok, n in b64.most_common(10):
                dec = b""
                try:
                    dec = base64.b64decode(tok + b"=" * (-len(tok) % 4), validate=False)
                except Exception:
                    pass
                print("    x%-3d %-46s -> %r" % (n, tok[:46].decode("latin-1"),
                                                dec[:60] if dec else b""))
        if hexstr:
            print("\n  hex-строки в payload: %d уникальных" % len(hexstr))

    if grep:
        needle = grep.encode() if isinstance(grep, str) else grep
        if not full:
            print("=== Поиск ===")
        print("\n  grep %r:" % needle)
        hits = 0
        for where, data in chunks:
            pos = data.find(needle)
            while pos >= 0 and hits < 200:
                hits += 1
                lo = max(0, pos - 60)
                frag = data[lo:pos + len(needle) + 60]
                print("    %s @%d: %s" % (where, pos, preview(frag, 200)))
                pos = data.find(needle, pos + 1)
        print("  всего вхождений: %d" % hits)


def to_json(collected, udp_flows, tcp_flows, path):
    st = collected["stats"]
    strong, weak, domains, b64, _hex = scan_findings(
        list(all_payload_chunks(collected, udp_flows, tcp_flows)))
    doc = {
        "file": path,
        "packets": st["packets"],
        "bytes": st["bytes"],
        "first_ts": collected["first_ts"],
        "last_ts": collected["last_ts"],
        "linktypes": {str(k): v for k, v in collected["linktypes"].items()},
        "stats": {k: v for k, v in st.items()},
        "dns": [{k: v for k, v in m.items() if k != "raw"} for m in collected["dns"]],
        "udp": [{
            "src": k[0], "sport": k[1], "dst": k[2], "dport": k[3],
            "count": f["count"], "bytes": f["bytes"],
            "first_ts": f["first_ts"], "last_ts": f["last_ts"],
            "datagrams": [{"ts": ts, "len": len(d),
                           "text": d.decode("utf-8", "replace") if is_text(d) else None,
                           "hex": d.hex() if len(d) <= 4096 else d[:4096].hex()}
                          for ts, d in f["dgrams"]],
        } for k, f in udp_flows],
        "tcp": [{
            "client": "%s:%d" % fl["client"], "server": "%s:%d" % fl["server"],
            "sni": fl["sni"],
            "packets": [fl["packets_c2s"], fl["packets_s2c"]],
            "c2s_len": fl["len_c2s"], "s2c_len": fl["len_s2c"],
            "syn": fl["syn"], "fin": fl["fin"], "rst": fl["rst"],
            "http": [
                {"dir": d, "kind": it["kind"], "first_line": it["first_line"],
                 "headers": it["headers"], "body_len": it["body_len"],
                 "body_text": it["body"].decode("utf-8", "replace") if is_text(it["body"]) else None}
                for d, data in (("c2s", fl["c2s"]), ("s2c", fl["s2c"]))
                for it in parse_http(data)
            ],
            "payload_c2s_text": fl["c2s"].decode("utf-8", "replace") if is_text(fl["c2s"]) else None,
            "payload_s2c_text": fl["s2c"].decode("utf-8", "replace") if is_text(fl["s2c"]) else None,
        } for fl in tcp_flows],
        "findings": {
            "flags": list(strong),
            "flags_weak": list(weak)[:20],
            "domains": dict(domains.most_common(40)),
            "base64_candidates": [{"token": t.decode("latin-1"), "count": n}
                                  for t, n in b64.most_common(20)],
        },
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, ensure_ascii=False, indent=1, default=str)
    print("[+] JSON записан: %s" % path)


def dump_streams(udp_flows, tcp_flows, outdir):
    os.makedirs(outdir, exist_ok=True)
    n = 0
    for (src, sport, dst, dport), f in udp_flows:
        joined = b"".join(d for _, d in f["dgrams"])
        name = os.path.join(outdir, "udp_%s_%d-%s_%d.bin" % (
            src.replace(":", "-"), sport, dst.replace(":", "-"), dport))
        with open(name, "wb") as fh:
            fh.write(joined)
        n += 1
    for i, fl in enumerate(tcp_flows):
        for tag in ("c2s", "s2c"):
            if fl[tag]:
                name = os.path.join(outdir, "tcp_%03d_%s.bin" % (i, tag))
                with open(name, "wb") as fh:
                    fh.write(fl[tag])
                n += 1
    print("[+] дамп потоков: %d файлов -> %s" % (n, outdir))


# -------------------------------------------------------------------- main --

def main():
    ap = argparse.ArgumentParser(
        description="Разбор PCAP/PCAPNG: DNS, UDP- и TCP-потоки, HTTP, поиск флагов.")
    ap.add_argument("pcap", help="файл .pcap/.pcapng (можно .gz)")
    ap.add_argument("--dns", action="store_true", help="показать DNS-запросы и ответы")
    ap.add_argument("--udp", action="store_true", help="показать UDP-потоки с payload")
    ap.add_argument("--tcp", action="store_true", help="показать TCP-потоки и HTTP")
    ap.add_argument("--all", action="store_true", help="всё: сводка + dns + udp + tcp + поиск")
    ap.add_argument("--json", metavar="FILE", help="выгрузить всё в JSON")
    ap.add_argument("--grep", metavar="STR", help="искать подстроку во всех payload")
    ap.add_argument("--hex", action="store_true", help="payload UDP как hex")
    ap.add_argument("--max-payload", type=int, default=300,
                    help="сколько байт payload печатать (по умолчанию 300)")
    ap.add_argument("--max-dgrams", type=int, default=0,
                    help="сколько датаграмм показывать в UDP-потоке (0 = все)")
    ap.add_argument("--limit", type=int, default=0,
                    help="сколько DNS-сообщений/потоков печатать (0 = все)")
    ap.add_argument("--dump", metavar="DIR", help="сохранить потоки в файлы")
    ap.add_argument("--no-summary", action="store_true", help="не печатать сводку")
    args = ap.parse_args()

    collected = collect(args.pcap)
    udp_flows = build_udp_flows(collected["udp"])
    tcp_flows = build_tcp_flows(collected["tcp"])

    explicit = args.dns or args.udp or args.tcp
    show_everything = args.all or (not explicit and not args.grep)

    if show_everything and not args.no_summary:
        show_summary(collected, udp_flows, tcp_flows)
    if show_everything:
        show_findings(collected, udp_flows, tcp_flows, args.grep, full=True)
    elif args.grep:
        show_findings(collected, udp_flows, tcp_flows, args.grep, full=False)

    if args.dns or args.all:
        print()
        show_dns(collected, args.limit)
    if args.udp or args.all:
        print()
        show_udp(udp_flows, args.hex, args.max_dgrams, args.max_payload, args.limit)
    if args.tcp or args.all:
        print()
        show_tcp(tcp_flows, args.max_payload, args.limit)

    if args.dump:
        dump_streams(udp_flows, tcp_flows, args.dump)
    if args.json:
        to_json(collected, udp_flows, tcp_flows, args.json)


if __name__ == "__main__":
    try:
        main()
    except (FileNotFoundError, IsADirectoryError, PermissionError) as e:
        print(f"[-] не могу открыть: {getattr(e, 'filename', None) or e}")
    except ValueError as e:
        print(f"[-] формат не понял: {e}")
    except BrokenPipeError:
        pass
    except KeyboardInterrupt:
        print("\n[-] прервано")
