#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
dir_fuzz.py — простой перебор директорий/файлов без gobuster.

  python dir_fuzz.py http://host
  python dir_fuzz.py http://host --wordlist words.txt --ext php,html
  python dir_fuzz.py http://host --status 200,301,302,403 --threads 20

Печатает только те коды, которые попросили (по умолчанию всё, кроме 404).
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
import concurrent.futures as cf

import requests

WORDS = """admin login register api api/v1 backup backups config config.php db dump
uploads upload files static assets images img css js scripts src app application
.git .env .svn .hg robots.txt sitemap.xml security.txt phpinfo.php info.php test
tests dev development staging old tmp temp logs log data private secret secrets
user users profile profiles account accounts dashboard panel cpanel admin.php
index.php index.html home main default error 404 500 server-status metrics
health healthz status debug console shell cmd exec include includes lib vendor
download downloads docs documentation readme README.md changelog LICENSE
""".split()


def check(base, path, statuses, timeout):
    url = base.rstrip("/") + "/" + path.lstrip("/")
    try:
        r = requests.get(url, timeout=timeout, allow_redirects=False)
    except requests.RequestException:
        return None
    if statuses and r.status_code not in statuses:
        return None
    return (r.status_code, len(r.content), url)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("url")
    ap.add_argument("--wordlist")
    ap.add_argument("--ext", default="", help="доп. расширения через запятую: php,html")
    ap.add_argument("--status", default="", help="какие коды показывать, например 200,301,403")
    ap.add_argument("--threads", type=int, default=16)
    ap.add_argument("--timeout", type=float, default=6)
    args = ap.parse_args()

    words = WORDS
    if args.wordlist:
        words = [l.strip() for l in open(args.wordlist, encoding="utf-8", errors="replace") if l.strip()]
    if args.ext:
        extra = []
        for w in words:
            for e in args.ext.split(","):
                if e.strip():
                    extra.append(f"{w}.{e.strip()}")
        words = list(dict.fromkeys(words + extra))

    statuses = {int(x) for x in args.status.split(",") if x.strip()}
    print(f"[+] слов: {len(words)}  threads={args.threads}")

    found = 0
    with cf.ThreadPoolExecutor(max_workers=args.threads) as ex:
        futs = [ex.submit(check, args.url, w, statuses, args.timeout) for w in words]
        for f in cf.as_completed(futs):
            r = f.result()
            if r:
                found += 1
                print(f"  {r[0]}  {r[1]:>8}  {r[2]}")
    print(f"[+] найдено: {found}")


if __name__ == "__main__":
    main()
