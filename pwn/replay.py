#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
replay.py — подключиться к сервису задачи и отправить данные (TCP или UDP).

  python replay.py 10.0.0.5 31337 --data "hello"
  python replay.py 10.0.0.5 4444 --udp --data @payload.bin
  python replay.py host 8080 --http --path /login

Зачем: половина сетевых задач — это «найди сервис, подключись и введи
условие». Раньше кит умел только TCP-payload для ret2win; UDP и текст
(как в `nc -u`) не умел вовсе.

Печатает всё, что сервис ответил; если в ответе есть флаг — показывает.
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
import sys
import time

FLAG_RX = re.compile(rb"[A-Za-z0-9_]{2,20}\{[\x20-\x7e]{3,80}\}")


def load_data(spec: str | None) -> bytes:
    if not spec:
        return b""
    if spec.startswith("@"):
        with open(spec[1:], "rb") as fh:
            return fh.read()
    return spec.encode("utf-8")


def talk_tcp(host, port, payload, wait, timeout):
    out = b""
    with socket.create_connection((host, port), timeout=timeout) as s:
        s.settimeout(2.0)
        try:
            out += s.recv(4096)
        except socket.timeout:
            pass
        if payload:
            s.sendall(payload + b"\n")
        t0 = time.time()
        while time.time() - t0 < wait:
            try:
                chunk = s.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            out += chunk
    return out


def talk_udp(host, port, payload, wait, timeout):
    out = b""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        s.sendto(payload or b"\n", (host, port))
        t0 = time.time()
        while time.time() - t0 < wait:
            try:
                chunk, _ = s.recvfrom(65535)
            except socket.timeout:
                break
            out += chunk
    return out


def talk_http(host, port, payload, wait, timeout, path="/"):
    body = payload or b""
    req = (f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
           f"Connection: close\r\n\r\n").encode()
    out = b""
    with socket.create_connection((host, port), timeout=timeout) as s:
        s.sendall(req)
        if body:
            s.sendall(body)
        t0 = time.time()
        while time.time() - t0 < wait:
            s.settimeout(max(0.5, wait - (time.time() - t0)))
            try:
                chunk = s.recv(8192)
            except socket.timeout:
                break
            if not chunk:
                break
            out += chunk
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("host")
    ap.add_argument("port", type=int)
    ap.add_argument("--data", "-d", default=None, help="текст или @файл")
    ap.add_argument("--udp", action="store_true", help="UDP (как nc -u)")
    ap.add_argument("--http", action="store_true", help="HTTP GET")
    ap.add_argument("--path", default="/", help="путь для --http")
    ap.add_argument("--wait", type=float, default=3.0, help="сколько ждать ответ")
    ap.add_argument("--timeout", type=float, default=8.0)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    if not (1 <= args.port <= 65535):
        print(f"[-] порт вне 1..65535: {args.port}")
        return 2
    try:
        payload = load_data(args.data)
    except OSError as exc:
        print(f"[-] не прочитал данные: {exc}")
        return 2

    try:
        if args.udp:
            out = talk_udp(args.host, args.port, payload, args.wait, args.timeout)
        elif args.http:
            out = talk_http(args.host, args.port, payload, args.wait,
                            args.timeout, args.path)
        else:
            out = talk_tcp(args.host, args.port, payload, args.wait, args.timeout)
    except OSError as exc:
        print(f"[-] не подключился: {exc}")
        return 1

    text = out.decode("utf-8", "replace")
    flags = [m.group(0).decode("latin-1") for m in FLAG_RX.finditer(out)]
    if args.json:
        print(json.dumps({"host": args.host, "port": args.port,
                          "udp": args.udp, "http": args.http,
                          "bytes": len(out), "flags": flags,
                          "response": text[:4000]}, ensure_ascii=False))
        return 0 if flags else 1
    print(f"[+] {args.host}:{args.port} "
          f"({'udp' if args.udp else 'http' if args.http else 'tcp'}), "
          f"ответ {len(out)} байт")
    if text.strip():
        for line in text.strip().splitlines()[:25]:
            print("    " + line[:200])
    else:
        print("    (пусто)")
    for f in dict.fromkeys(flags):
        print(f"[!!!] ФЛАГ: {f}")
    return 0 if flags else 1


if __name__ == "__main__":
    raise SystemExit(main())
