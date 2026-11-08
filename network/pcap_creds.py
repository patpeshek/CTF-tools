#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
pcap_creds.py — вытащить логины/пароли/токены из трафика.

  python pcap_creds.py capture.pcap
  python pcap_creds.py capture.pcap --all-ports

Ищет: HTTP Basic, формы логина, FTP USER/PASS, IRC PASS/NICK, SMTP AUTH,
Telnet-приглашения.
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
import re
import urllib.parse as up

from scapy.all import IP, TCP, PcapReader, Raw

BASIC = re.compile(rb"Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)", re.I)
FORM = re.compile(rb"(?:username|user|login|email)=([^&\s]{1,80})&(?:password|pass|pwd)=([^&\s]{1,80})", re.I)
FTP_USER = re.compile(rb"(?:^|\r\n)USER\s+(\S+)", re.I)
FTP_PASS = re.compile(rb"(?:^|\r\n)PASS\s+(\S+)", re.I)
IRC_PASS = re.compile(rb"(?:^|\r\n)PASS\s+(\S+)", re.I)
SMTP_AUTH = re.compile(rb"AUTH\s+PLAIN\s+([A-Za-z0-9+/=]+)", re.I)
TELNET_HINT = re.compile(rb"(?i)(login|password|username)\s*[:>]\s*(\S{1,40})")


def decode_plain(b64: bytes):
    try:
        raw = base64.b64decode(b64 + b"=" * (-len(b64) % 4))
        return raw.replace(b"\x00", b" ").decode("utf-8", "replace")
    except Exception:
        return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("pcap")
    ap.add_argument("--all-ports", action="store_true")
    args = ap.parse_args()

    n = 0
    with PcapReader(args.pcap) as pr:
        for p in pr:
            if TCP not in p or Raw not in p:
                continue
            t = p[TCP]
            if not args.all_ports and not (t.dport in (21, 23, 25, 80, 110, 143, 443, 6667, 8080)
                                           or t.sport in (21, 23, 25, 80, 110, 143, 6667, 8080)):
                continue
            data = bytes(p[Raw].load)
            src = p[IP].src if IP in p else "?"
            dst = p[IP].dst if IP in p else "?"
            ports = {t.sport, t.dport}

            if 80 in ports or 8080 in ports or 8000 in ports or 3000 in ports:
                for m in BASIC.finditer(data):
                    dec = decode_plain(m.group(1))
                    if dec:
                        n += 1
                        print(f"[HTTP Basic] {src}->{dst}: {dec}")

                for m in FORM.finditer(data):
                    n += 1
                    u = up.unquote(m.group(1).decode("latin-1"))
                    pw = up.unquote(m.group(2).decode("latin-1"))
                    print(f"[HTTP form] {src}->{dst}: {u} / {pw}")

            if 21 in ports:
                users = FTP_USER.findall(data)
                passes = FTP_PASS.findall(data)
                if users or passes:
                    n += 1
                    print(f"[FTP] {src}->{dst}: user={[x.decode('latin-1') for x in users]} "
                          f"pass={[x.decode('latin-1') for x in passes]}")

            if 6667 in ports or 6697 in ports:
                for m in IRC_PASS.finditer(data):
                    n += 1
                    print(f"[IRC] {src}->{dst}: PASS {m.group(1).decode('latin-1')}")

            if 25 in ports or 587 in ports or 465 in ports:
                for m in SMTP_AUTH.finditer(data):
                    dec = decode_plain(m.group(1))
                    if dec:
                        n += 1
                        print(f"[SMTP AUTH] {src}->{dst}: {dec}")

            if 23 in ports:
                for m in TELNET_HINT.finditer(data):
                    n += 1
                    print(f"[telnet?] {src}->{dst}: {m.group(0)[:80].decode('latin-1')}")

    print(f"\n[+] находок: {n}")
    if not n:
        print("[i] проверь --all-ports; для TLS нужен ключ/расшифровка, для SMB/NTLM — отдельный разбор")


if __name__ == "__main__":
    try:
        main()
    except (FileNotFoundError, IsADirectoryError, PermissionError) as e:
        print(f"[-] не могу открыть: {getattr(e, 'filename', None) or e}")
    except BrokenPipeError:
        pass
    except KeyboardInterrupt:
        print("\n[-] прервано")
