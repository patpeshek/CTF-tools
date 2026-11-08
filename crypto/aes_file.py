#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
aes_file.py — расшифровать файл AES, когда ключ/IV «спрятаны» в бинарнике.

Типовой кейс: строка ключа XOR-ится числом, потом дублируется
до нужной длины; IV из строки короче 16 дополняется повтором и обрезается.

  # ключ/IV ещё не известны: перебрать строки из шифратора
  python aes_file.py secret.enc --auto --from-bin encryptor
  python aes_file.py secret.enc --auto --from-bin encryptor --top 10

  python aes_file.py secret.enc --key SECRET_KEY_STRING --key-xor 42 --keylen 32 \
      --iv MY_IV_STRING --ivlen 16
  python aes_file.py secret.enc --key-hex 0011... --iv-hex 2233...

`--auto` пробует строки бинарника как ключ/IV, их md5/sha1/sha256,
дополнение повтором/нулями до 16/24/32 байт, режимы CBC (нулевой IV,
первые 16 байт файла, md5 строки) и ECB; печатает самые «текстовые» варианты.
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
import binascii
import hashlib
import os
import re
import sys

from Crypto.Cipher import AES

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import common  # noqa: E402


def build_bytes(text: str, want: int, xor: int = 0) -> bytes:
    raw = bytes((ord(c) ^ xor) & 0xFF for c in text) if xor else text.encode()
    if len(raw) < want:
        raw = (raw * ((want // len(raw)) + 1))[:want]
    return raw[:want]


def strip_pkcs7(data: bytes) -> bytes:
    if not data:
        return data
    pad = data[-1]
    if 1 <= pad <= 16 and data.endswith(bytes([pad]) * pad):
        return data[:-pad]
    return data


def _strings(data: bytes, lo: int = 4, hi: int = 64):
    """Печатные строки из бинарника — кандидаты в ключи/IV."""
    out = []
    for m in re.finditer(rb"[ -~]{%d,%d}" % (lo, hi), data):
        out.append(m.group().decode("latin-1"))
    return out


def _key_variants(text: str):
    """Как из строки делают ключ в самодельных шифраторах."""
    raw = text.encode("latin-1", "replace")
    if not raw:
        return set()
    cands = {raw, hashlib.md5(raw).digest(), hashlib.sha256(raw).digest(),
             hashlib.sha1(raw).digest()[:16]}
    for n in (16, 24, 32):
        if len(raw) < n:
            cands.add((raw * (n // len(raw) + 1))[:n])
            cands.add(raw.ljust(n, b"\x00"))
        else:
            cands.add(raw[:n])
    return {c for c in cands if len(c) in (16, 24, 32)}


def _score(plain: bytes) -> tuple[int, str]:
    """Насколько результат похож на текст. Больше — лучше."""
    if not plain:
        return -1000, ""
    printable = sum(32 <= c < 127 or c in (9, 10, 13) for c in plain) / len(plain)
    text = plain.decode("utf-8", "replace")
    score = int(printable * 60)
    if printable > 0.95:
        score += 10
    low = text.lower()
    for word in ("flag", "ctf{", "secret", "password", "the ", "this ", "{", "}"):
        if word in low:
            score += 15
    if common.find_flags(plain):
        score += 100
    if low.startswith(("this is", "hello", "ctf{", "flag{")):
        score += 30
    return score, text


def auto_crack(data: bytes, key_texts, explicit_keys, iv_texts, explicit_ivs, top=5):
    """Перебрать ключи/IV/режимы и вернуть лучшие расшифровки."""
    keys = set(explicit_keys)
    for t in key_texts:
        keys |= _key_variants(t)
    ivs = {b"\x00" * 16, data[:16]}
    ivs |= set(explicit_ivs)
    for t in iv_texts:
        raw = t.encode("latin-1", "replace")
        ivs.add(raw[:16].ljust(16, b"\x00"))
        ivs.add(hashlib.md5(raw).digest())

    results = []
    for key in keys:
        for iv in ivs:
            for mode, name in ((AES.MODE_CBC, "CBC"), (AES.MODE_ECB, "ECB")):
                if len(data) % 16:
                    continue
                try:
                    if mode == AES.MODE_CBC:
                        plain = AES.new(key, mode, iv).decrypt(data)
                    else:
                        plain = AES.new(key, mode).decrypt(data)
                except ValueError:
                    continue
                plain = strip_pkcs7(plain)
                score, text = _score(plain)
                results.append((score, name, key, iv if mode == AES.MODE_CBC else b"", text))
    results.sort(key=lambda r: r[0], reverse=True)
    seen = set()
    shown = 0
    for score, name, key, iv, text in results:
        sig = text[:40]
        if sig in seen:
            continue
        seen.add(sig)
        shown += 1
        print(f"\n[{score:>4}] {name} key={key.hex()} iv={iv.hex() or '-'}")
        print("       ", text[:200].replace("\n", " ")[:200])
        for f in common.find_flags(text.encode("utf-8", "replace")):
            print("        [!!!] ФЛАГ:", f)
        if shown >= top:
            break
    return results[0] if results else None


def load_input(path: str) -> bytes:
    """Файл или hex/base64-текст внутри него."""
    data = open(path, "rb").read()
    head = data[:200].strip()
    if head and all(c in b"0123456789abcdefABCDEF\r\n \t" for c in head) and len(head) >= 32:
        try:
            return binascii.unhexlify(re.sub(rb"\s", b"", data))
        except binascii.Error:
            pass
    if head[:5] == b"-----":
        pass
    try:
        import base64
        txt = re.sub(rb"\s", b"", data)
        if len(txt) >= 16 and len(txt) % 4 == 0 and re.fullmatch(rb"[A-Za-z0-9+/=]+", txt):
            return base64.b64decode(txt)
    except Exception:
        pass
    return data


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("file")
    ap.add_argument("--key")
    ap.add_argument("--key-hex")
    ap.add_argument("--key-xor", type=int, default=0)
    ap.add_argument("--keylen", type=int, default=32)
    ap.add_argument("--iv")
    ap.add_argument("--iv-hex")
    ap.add_argument("--ivlen", type=int, default=16)
    ap.add_argument("--no-unpad", action="store_true")
    ap.add_argument("--auto", action="store_true",
                    help="перебрать ключи/IV/ECB-CBC (строки из --from-bin и хеши)")
    ap.add_argument("--from-bin", help="бинарник, откуда взять строки для ключа/IV")
    ap.add_argument("--top", type=int, default=5, help="сколько вариантов показать")
    args = ap.parse_args()

    data = load_input(args.file)
    if args.auto:
        key_texts = _strings(open(args.from_bin, "rb").read()) if args.from_bin else []
        if not key_texts:
            key_texts = _strings(data)
        explicit_keys = []
        if args.key_hex:
            explicit_keys.append(binascii.unhexlify(args.key_hex))
        if args.key:
            explicit_keys.append(build_bytes(args.key, args.keylen, args.key_xor))
        explicit_ivs = []
        if args.iv_hex:
            explicit_ivs.append(binascii.unhexlify(args.iv_hex))
        if args.iv:
            explicit_ivs.append(build_bytes(args.iv, args.ivlen))
        print(f"[+] данных: {len(data)} байт; строк-кандидатов: {len(key_texts)}")
        if len(data) % 16:
            print(f"[!] длина не кратна 16 ({len(data)}) — возможно, файл обрезан")
        auto_crack(data, key_texts, explicit_keys, key_texts, explicit_ivs, args.top)
        return

    if args.key_hex:
        key = binascii.unhexlify(args.key_hex)
    elif args.key:
        key = build_bytes(args.key, args.keylen, args.key_xor)
    else:
        ap.error("нужен --key/--key-hex (или --auto)")
    if args.iv_hex:
        iv = binascii.unhexlify(args.iv_hex)
    elif args.iv:
        iv = build_bytes(args.iv, args.ivlen)
    else:
        ap.error("нужен --iv/--iv-hex (или --auto)")

    print(f"[+] key ({len(key)}): {key.hex()}")
    print(f"[+] iv  ({len(iv)}): {iv.hex()}")

    cipher = AES.new(key, AES.MODE_CBC, iv)
    plain = cipher.decrypt(data)
    if not args.no_unpad:
        plain = strip_pkcs7(plain)

    print("\n[+] hex (первые 64):", plain[:64].hex())
    print("[+] текст:")
    print(plain.decode("utf-8", "replace")[:2000])


if __name__ == "__main__":
    main()
