#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
recon.py — быстрая разведка одной веб-страницы.

  python recon.py "http://host/"
  python recon.py "http://host/?id=1" --cookie "sid=abc"
  python recon.py "http://host/" --no-robots

Что делает:
  * статус, заголовки, куки, технологии по заголовкам;
  * флаги в теле/заголовках;
  * HTML-комментарии, ссылки, формы и их параметры;
  * inline-JS: подозрительные строки (flag/secret/token/api/key), base64-блобы;
  * JWT в куках/строках: декодирует header/payload;
  * robots.txt и sitemap.xml (если не --no-robots);
  * подсказывает следующие команды (param/jwt/ssti/dirfuzz).

Только GET, только указанный хост, никакого брутфорса.
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
import json
import os
import re
import sys
import urllib.parse as up
from html.parser import HTMLParser

import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import common  # noqa: E402

INTEREST = ("flag", "secret", "token", "api", "key", "admin", "debug", "backup",
            "hidden", "internal", "staging", "password", "passwd", "config")
JWT_RE = re.compile(rb"eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{0,}")


class Page(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links, self.forms, self.comments, self.scripts = [], [], [], []
        self._in_script = False
        self._form = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "a" and a.get("href"):
            self.links.append(a["href"])
        elif tag in ("script", "img", "iframe", "link") and (a.get("src") or a.get("href")):
            self.links.append(a.get("src") or a.get("href"))
        elif tag == "script":
            self._in_script = True
        elif tag == "form":
            self._form = {"action": a.get("action", ""), "method": (a.get("method") or "get").upper(),
                          "inputs": []}
            self.forms.append(self._form)
        elif tag in ("input", "textarea", "select") and self._form is not None:
            if a.get("name"):
                self._form["inputs"].append(a["name"])

    def handle_endtag(self, tag):
        if tag == "script":
            self._in_script = False
        elif tag == "form":
            self._form = None

    def handle_data(self, data):
        if self._in_script:
            self.scripts.append(data)

    def handle_comment(self, data):
        if data.strip():
            self.comments.append(data.strip())


def decode_jwt(tok: str):
    try:
        head, body, _ = tok.split(".")
        def part(p):
            return json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))
        return part(head), part(body)
    except Exception:
        return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("url")
    ap.add_argument("--cookie", help="Cookie: ...")
    ap.add_argument("--header", action="append", default=[], help="доп. заголовок K:V")
    ap.add_argument("--timeout", type=float, default=10.0)
    ap.add_argument("--no-robots", action="store_true")
    ap.add_argument("--max-links", type=int, default=40)
    common.add_flag_args(ap)
    args = ap.parse_args()
    common.apply_flag_args(args)

    headers = {"User-Agent": "Mozilla/5.0 (recon)"}
    for h in args.header:
        if ":" in h:
            k, v = h.split(":", 1)
            headers[k.strip()] = v.strip()
    if args.cookie:
        headers["Cookie"] = args.cookie

    try:
        r = requests.get(args.url, headers=headers, timeout=args.timeout, allow_redirects=True)
    except requests.RequestException as e:
        print("[-] запрос не удался:", e)
        return
    body = r.text or ""
    print(f"[+] {r.status_code} {r.url}  {len(body)} символов")
    for h in ("Server", "X-Powered-By", "Set-Cookie", "Location", "Content-Type", "Via", "X-Backend"):
        if h in r.headers:
            print(f"    {h}: {r.headers[h][:160]}")

    flags = common.find_flags((body + str(dict(r.headers))).encode("utf-8", "replace"))
    for f in dict.fromkeys(flags):
        print("[!!!] ФЛАГ:", f)

    # куки
    for c in r.cookies:
        val = c.value or ""
        if len(val) > 20:
            print(f"[+] кука {c.name} = {val[:80]}{'…' if len(val) > 80 else ''}")

    # JWT
    jwts = {m.group().decode() for m in JWT_RE.finditer(body.encode("utf-8", "replace"))}
    for c in r.cookies:
        if JWT_RE.match((c.value or "").encode()):
            jwts.add(c.value)
    for tok in list(jwts)[:5]:
        dec = decode_jwt(tok)
        if dec:
            print(f"[+] JWT: {dec[1]}")
            print(f"    header: {dec[0]}")

    page = Page()
    try:
        page.feed(body)
    except Exception:
        pass

    if page.comments:
        print(f"[+] HTML-комментарии ({len(page.comments)}):")
        for c in page.comments[:8]:
            print("    <!--", c[:200].replace("\n", " "), "-->")

    if page.forms:
        print(f"[+] формы ({len(page.forms)}):")
        for f in page.forms[:8]:
            print(f"    {f['method']} {f['action'] or '(сама страница)'}  inputs={f['inputs']}")

    # ссылки: только свой хост, убрать дубли
    base = up.urlparse(r.url)
    seen, links = set(), []
    for href in page.links:
        if not href or href.startswith(("javascript:", "mailto:", "#")):
            continue
        full = up.urljoin(r.url, href)
        p = up.urlparse(full)
        if p.netloc != base.netloc:
            continue
        key = p.path + ("?" + p.query if p.query else "")
        if key in seen:
            continue
        seen.add(key)
        links.append(full)
    if links:
        print(f"[+] ссылки на том же хосте ({len(links)}):")
        for u in links[:args.max_links]:
            print("    ", u)

    # inline JS
    js = "\n".join(page.scripts)
    if js.strip():
        hits = [ln.strip()[:160] for ln in js.splitlines()
                if any(k in ln.lower() for k in INTEREST)]
        if hits:
            print(f"[+] подозрительные строки в JS ({len(hits)}):")
            for h in hits[:10]:
                print("    ", h)
        for m in re.finditer(r"[A-Za-z0-9+/]{12,}={0,2}", js):
            try:
                dec = base64.b64decode(m.group() + "=" * (-len(m.group()) % 4)).decode("utf-8")
            except Exception:
                continue
            if common.printable_ratio(dec) > 0.9:
                print("    b64 в JS:", dec[:120])
                for f in common.find_flags(dec.encode()):
                    print("[!!!] ФЛАГ (b64 в JS):", f)

    # robots/sitemap
    if not args.no_robots:
        for path in ("/robots.txt", "/sitemap.xml"):
            u = up.urljoin(f"{base.scheme}://{base.netloc}", path)
            try:
                rr = requests.get(u, headers=headers, timeout=args.timeout)
            except requests.RequestException:
                continue
            if rr.status_code == 200 and rr.text.strip():
                if path.endswith(".xml") and "urlset" not in rr.text and "<?xml" not in rr.text:
                    continue  # сервер отдал страницу вместо sitemap
                print(f"[+] {path} ({len(rr.text)} b):")
                for line in rr.text.splitlines()[:15]:
                    print("    ", line[:160])
                for f in common.find_flags(rr.text.encode()):
                    print("[!!!] ФЛАГ в", path, ":", f)

    # что дальше
    print("\n[i] дальше:")
    if "?" in r.url or page.forms:
        print(f'    python toolbox.py param "{r.url}"')
    print(f'    python toolbox.py dirfuzz {base.scheme}://{base.netloc}')
    if jwts:
        print("    python toolbox.py jwt decode <token>   (или jwtbrute, если есть подпись)")
    print(f'    python toolbox.py solve "{args.url}"')


if __name__ == "__main__":
    main()
