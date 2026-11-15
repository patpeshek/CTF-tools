#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
js_secret.py — секреты в комментариях JS: токены, ключи, UUID.

  python js_secret.py --text "^^^16_.3*c320*1/21*^1-6*_2/^_-35a-b-"
  python js_secret.py http://127.0.0.1:8000/
  python js_secret.py http://host/ --json

Зачем: в задачах dev-токен часто оставлен в комментарии и «зашифрован»
простейшей функцией (`reverse().map(c => c.charCodeAt(0)+3)`). Инструмент
собирает `//` и `/* */`, вытаскивает строки и пробует сдвиги ±N, reverse,
ROT13 и base64 — ищет UUID/hex/токены.
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
import codecs
import json
import re
import sys
import urllib.request

UUID_RX = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I)
HEX_RX = re.compile(r"^[0-9a-f]{16,}$", re.I)
TOKEN_RX = re.compile(r"^[A-Za-z0-9_\-\.]{20,}$")
COMMENT_RX = re.compile(r"//[^\n]*|/\*.*?\*/", re.S)
STR_RX = re.compile(r"['\"]([^'\"\n]{6,200})['\"]")


def transforms(s: str):
    yield "как есть", s
    yield "reverse", s[::-1]
    yield "rot13", codecs.decode(s, "rot13")
    for n in range(1, 26):
        yield f"+{n}", "".join(chr(ord(c) + n) for c in s)
        yield f"-{n}", "".join(chr(ord(c) - n) for c in s)
    try:
        raw = base64.b64decode(s + "=" * (-len(s) % 4))
        yield "base64", raw.decode("utf-8", "replace")
    except Exception:
        pass
    # reverse + сдвиг (частый паттерн с лишним reverse в декодере)
    for n in (3, -3, 1, -1):
        yield f"rev+{n}", "".join(chr(ord(c) + n) for c in s[::-1])


def looks_interesting(text: str) -> bool:
    t = text.strip()
    if UUID_RX.search(t):
        return True
    if HEX_RX.match(t) and len(t) >= 16:
        return True
    if TOKEN_RX.match(t) and len(t) >= 20:
        return True
    if re.search(r"[A-Za-z0-9_]{2,20}\{[ -~]{3,80}\}", t):
        return True
    return False


def analyse(text: str, source: str = "text"):
    hits = []
    for c in COMMENT_RX.findall(text):
        for s in STR_RX.findall(c) + [c]:
            for name, val in transforms(s):
                if looks_interesting(val) and val != s:
                    hits.append({"source": source, "comment": c[:120],
                                 "transform": name, "value": val[:200]})
    # дедуп
    seen, out = set(), []
    for h in hits:
        key = (h["transform"], h["value"])
        if key in seen:
            continue
        seen.add(key)
        out.append(h)
    return out


def fetch(url: str, timeout=6) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", "replace")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("url", nargs="?")
    ap.add_argument("--text", default=None)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    sources = []
    if args.text:
        sources.append(("--text", args.text))
    if args.url:
        base = args.url.rstrip("/")
        try:
            html = fetch(base + "/")
        except OSError as exc:
            print(f"[-] не открыл {args.url}: {exc}")
            return 2
        sources.append((base + "/", html))
        for src in re.findall(r'src="([^"]+\.js[^"]*)"', html):
            u = src if src.startswith("http") else base + ("/" + src.lstrip("/"))
            try:
                sources.append((u, fetch(u)))
            except OSError:
                continue

    all_hits = []
    for name, text in sources:
        all_hits += analyse(text, name)

    if args.json:
        print(json.dumps({"hits": all_hits}, ensure_ascii=False))
        return 0 if all_hits else 1
    print(f"[+] источников: {len(sources)}, находок: {len(all_hits)}")
    for h in all_hits[:20]:
        print(f"    [{h['transform']}] {h['value']}   ({h['source']})")
    return 0 if all_hits else 1


if __name__ == "__main__":
    raise SystemExit(main())
