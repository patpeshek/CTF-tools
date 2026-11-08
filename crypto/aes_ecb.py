#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
aes_ecb.py — детект и расшифровка AES-ECB.

  python aes_ecb.py cipher.bin
  python aes_ecb.py cipher.hex --hex --key secret --decrypt
  python aes_ecb.py cipher.bin --key 00112233445566778899aabbccddeeff --key-enc hex

Детект: одинаковые 16-байтные блоки (ECB не использует IV).
"""

from __future__ import annotations

import argparse
# Windows: консоль/pipe не должны падать на Unicode (—, →, «», █).
try:
    import sys as _sys
    for _stream in (_sys.stdout, _sys.stderr):
        _stream.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass
import base64
import binascii
import re
from collections import Counter

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

BLOCK = 16


def load_cipher(text: str, is_hex: bool):
    if is_hex:
        return bytes.fromhex(re.sub(r"(?i)0x|[\s:]", "", text))
    return text.encode("latin-1")


def key_variants(s: str):
    out = [("raw", s.encode())]
    try:
        out.append(("hex", bytes.fromhex(re.sub(r"(?i)0x|[\s:]", "", s))))
    except ValueError:
        pass
    try:
        out.append(("base64", base64.b64decode(s + "=" * (-len(s) % 4))))
    except Exception:
        pass
    return out


def strip_pad(b: bytes) -> bytes:
    try:
        return unpad(b, BLOCK)
    except ValueError:
        return b


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("file")
    ap.add_argument("--hex", action="store_true", help="файл содержит hex-текст")
    ap.add_argument("--key")
    ap.add_argument("--key-enc", choices=["raw", "hex", "base64"])
    ap.add_argument("--decrypt", action="store_true")
    ap.add_argument("--blocks", action="store_true", help="показать блоки")
    args = ap.parse_args()

    if args.hex:
        data = load_cipher(open(args.file, encoding="utf-8").read(), True)
    else:
        data = open(args.file, "rb").read()

    print(f"[+] размер: {len(data)} b, блоков: {len(data)//BLOCK}")
    blocks = [data[i:i + BLOCK] for i in range(0, len(data) - BLOCK + 1, BLOCK)]
    cnt = Counter(blocks)
    dup = {b: n for b, n in cnt.items() if n > 1}
    print(f"[+] уникальных блоков: {len(cnt)} / {len(blocks)}")
    if dup:
        print(f"[!!!] ECB: {len(dup)} повторяющихся блоков")
        for b, n in list(dup.items())[:5]:
            print(f"    x{n}  {b.hex()}")
    else:
        print("[i] повторов нет: это не ECB (или данных мало)")

    if args.blocks:
        for i, b in enumerate(blocks[:20]):
            print(f"  {i:3d}  {b.hex()}  {b!r}")

    if not args.decrypt:
        return
    if not args.key:
        print("[-] для расшифровки нужен --key")
        return

    variants = key_variants(args.key) if not args.key_enc else [
        (args.key_enc, {
            "raw": lambda s: s.encode(),
            "hex": lambda s: bytes.fromhex(re.sub(r"(?i)0x|[\s:]", "", s)),
            "base64": lambda s: base64.b64decode(s + "=" * (-len(s) % 4)),
        }[args.key_enc](args.key))
    ]
    for how, key in variants:
        if len(key) not in (16, 24, 32):
            continue
        try:
            dec = AES.new(key, AES.MODE_ECB).decrypt(data)
        except Exception as e:
            print(f"[-] {how}: {e}")
            continue
        plain = strip_pad(dec)
        text = plain.decode("utf-8", "replace")
        printable = sum(32 <= ord(c) < 127 for c in text) / max(1, len(text))
        if printable > 0.7 or "{" in text:
            print(f"\n[+] key={how} ({len(key)} b)")
            print(text[:800])


if __name__ == "__main__":
    try:
        main()
    except (FileNotFoundError, IsADirectoryError, PermissionError) as e:
        print(f"[-] не могу открыть: {getattr(e, 'filename', None) or e}")
    except BrokenPipeError:
        pass
    except KeyboardInterrupt:
        print("\n[-] прервано")
