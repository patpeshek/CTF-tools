#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
browser_artifacts.py — история, куки, логины, закладки из профиля браузера.

  python browser_artifacts.py "C:\\Users\\user\\AppData\\Local\\Google\\Chrome\\User Data"
  python browser_artifacts.py path/to/History --json

Chrome/Edge: History, Cookies, Login Data, Bookmarks, Web Data, Downloads.
Firefox: places.sqlite, cookies.sqlite, logins.json.
Значения куки/паролей в Chrome зашифрованы (DPAPI/OS crypt) — показываем как есть.
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
import json
import os
import re
import sqlite3
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import common  # noqa: E402


def q(db, sql):
    try:
        con = sqlite3.connect(f"file:{db}?mode=ro&immutable=1", uri=True)
        cur = con.cursor()
        rows = cur.execute(sql).fetchall()
        con.close()
        return rows
    except Exception:
        return []


def chrome_time(t):
    try:
        return t / 1_000_000 - 11644473600
    except Exception:
        return None


def scan_db(path, out):
    name = os.path.basename(path)
    low = name.lower()
    if low == "history":
        for url, title, cnt, last in q(path, "select url,title,visit_count,last_visit_time "
                                             "from urls order by last_visit_time desc limit 200"):
            out.append({"type": "history", "url": url, "title": title,
                        "visits": cnt, "last": chrome_time(last)})
    elif low == "cookies":
        for host, name_, val, enc in q(path, "select host_key,name,value,encrypted_value "
                                             "from cookies limit 300"):
            out.append({"type": "cookie", "host": host, "name": name_,
                        "value": val or "", "encrypted": bool(enc)})
    elif low == "login data":
        for origin, user, pw in q(path, "select origin_url,username_value,password_value "
                                        "from logins limit 200"):
            out.append({"type": "login", "url": origin, "user": user,
                        "password_encrypted": bool(pw)})
    elif low == "web data":
        for name_, val in q(path, "select name,value from autofill limit 200"):
            out.append({"type": "autofill", "name": name_, "value": val})
    elif low in ("places.sqlite",):
        for url, title, cnt in q(path, "select url,title,visit_count from moz_places "
                                        "order by last_visit_date desc limit 200"):
            out.append({"type": "firefox_history", "url": url, "title": title, "visits": cnt})
    elif low == "cookies.sqlite":
        for host, name_, val in q(path, "select host,name,value from moz_cookies limit 300"):
            out.append({"type": "firefox_cookie", "host": host, "name": name_, "value": val})


def scan_bookmarks(path, out):
    try:
        data = json.load(open(path, encoding="utf-8", errors="replace"))
    except Exception:
        return

    def walk(node):
        if isinstance(node, dict):
            if node.get("type") == "url" and node.get("url"):
                out.append({"type": "bookmark", "url": node["url"], "name": node.get("name")})
            for v in node.values():
                walk(v)
        elif isinstance(node, list):
            for v in node:
                walk(v)
    walk(data)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("path")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--limit", type=int, default=500)
    common.add_flag_args(ap)
    args = ap.parse_args()
    common.apply_flag_args(args)

    out = []
    if os.path.isdir(args.path):
        for root, _, files in os.walk(args.path):
            for f in files:
                p = os.path.join(root, f)
                low = f.lower()
                if low in ("history", "cookies", "login data", "web data",
                           "places.sqlite", "cookies.sqlite"):
                    scan_db(p, out)
                elif low == "bookmarks":
                    scan_bookmarks(p, out)
                elif low == "logins.json":
                    try:
                        data = json.load(open(p, encoding="utf-8", errors="replace"))
                        for x in data.get("logins", []):
                            out.append({"type": "firefox_login",
                                        "url": x.get("hostname"), "user": x.get("usernameField")})
                    except Exception:
                        pass
    else:
        scan_db(args.path, out)

    flags = set()
    for x in out:
        blob = " ".join(str(v) for v in x.values())
        flags.update(common.find_flags(blob.encode("utf-8", "replace")))
    urls = sorted({x.get("url") for x in out if x.get("url")})

    print(f"[+] записей: {len(out)}  URL: {len(urls)}")
    for x in out[:args.limit]:
        print("  ", x)
    if flags:
        print("\n=== ФЛАГИ ===")
        for f in sorted(flags):
            print(" !!!", f)

    if args.json:
        print(json.dumps({"items": out, "flags": sorted(flags)}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
