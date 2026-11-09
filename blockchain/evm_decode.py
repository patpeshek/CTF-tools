#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""evm_decode.py — calldata смарт-контракта: селектор, аргументы, события.

  python evm_decode.py 0xa9059cbb000...
  python evm_decode.py calldata.txt --json out.json
  python evm_decode.py --sig "transfer(address,uint256)"

Ethereum использует Keccak-256 (не SHA3-256): селектор — первые 4 байта хеша
от сигнатуры. Известные селекторы распознаются, неизвестные печатаются
словами по 32 байта — дальше видно глазами.
"""
from __future__ import annotations

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
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import common  # noqa: E402

SELECTORS = {
    "a9059cbb": ("transfer(address,uint256)", ["address", "uint256"]),
    "23b872dd": ("transferFrom(address,address,uint256)",
                 ["address", "address", "uint256"]),
    "095ea7b3": ("approve(address,uint256)", ["address", "uint256"]),
    "70a08231": ("balanceOf(address)", ["address"]),
    "18160ddd": ("totalSupply()", []),
    "dd62ed3e": ("allowance(address,address)", ["address", "address"]),
    "6352211e": ("ownerOf(uint256)", ["uint256"]),
    "42842e0e": ("safeTransferFrom(address,address,uint256)",
                 ["address", "address", "uint256"]),
    "a22cb465": ("setApprovalForAll(address,bool)", ["address", "bool"]),
    "8da5cb5b": ("owner()", []),
    "f2fde38b": ("transferOwnership(address)", ["address"]),
    "715018a6": ("renounceOwnership()", []),
    "40c10f19": ("mint(address,uint256)", ["address", "uint256"]),
    "42966c68": ("burn(uint256)", ["uint256"]),
    "2e1a7d4d": ("withdraw(uint256)", ["uint256"]),
    "d0e30db0": ("deposit()", []),
    "3659cfe6": ("upgradeTo(address)", ["address"]),
    "4f1ef286": ("upgradeToAndCall(address,bytes)", ["address", "bytes"]),
    "5c975abb": ("paused()", []),
    "8456cb59": ("pause()", []),
    "3f4ba83a": ("unpause()", []),
    "f3fef3a3": ("withdraw(address,uint256)", ["address", "uint256"]),
    "b6b55f25": ("deposit(uint256)", ["uint256"]),
    "e8eda9df": ("deposit(address,uint256,address,uint16)",
                 ["address", "uint256", "address", "uint16"]),
    "69328dec": ("withdraw(address,uint256,address)", ["address", "uint256", "address"]),
}


def keccak_selector(signature: str) -> str:
    try:
        from Crypto.Hash import keccak
    except ImportError:
        return ""
    k = keccak.new(digest_bits=256)
    k.update(signature.encode())
    return k.hexdigest()[:8]


def word(data: bytes, i: int) -> bytes:
    return data[i * 32:(i + 1) * 32].ljust(32, b"\x00")


def decode_arg(kind: str, raw: bytes, body: bytes, index: int):
    if kind == "address":
        return "0x" + raw[-20:].hex()
    if kind == "bool":
        return bool(int.from_bytes(raw, "big"))
    if kind.startswith("uint") or kind.startswith("int"):
        value = int.from_bytes(raw, "big", signed=kind.startswith("int"))
        return value
    if kind == "bytes32":
        return "0x" + raw.hex()
    if kind in ("bytes", "string"):
        offset = int.from_bytes(raw, "big")
        if offset + 32 > len(body):
            return None
        length = int.from_bytes(body[offset:offset + 32], "big")
        chunk = body[offset + 32:offset + 32 + length]
        return chunk.decode("utf-8", "replace") if kind == "string" else "0x" + chunk.hex()
    return "0x" + raw.hex()


def decode(hexstr: str):
    s = re.sub(r"(?i)0x|[\s:]", "", hexstr.strip())
    if not re.fullmatch(r"[0-9a-fA-F]+", s or "") or len(s) < 8:
        return None
    data = bytes.fromhex(s)
    sel = data[:4].hex()
    body = data[4:]
    sig, types = SELECTORS.get(sel, (None, []))
    words = max(0, len(body) // 32)
    args = {}
    note = []
    for i, kind in enumerate(types):
        if i >= words:
            note.append(f"нет слова для аргумента #{i} ({kind})")
            break
        args[f"arg{i}"] = decode_arg(kind, word(body, i), body, i)
    return {
        "selector": "0x" + sel,
        "signature": sig,
        "known": bool(sig),
        "args": args,
        "words": words,
        "note": note,
        "raw_words": ["0x" + body[i * 32:(i + 1) * 32].hex() for i in range(min(words, 16))],
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("calldata", nargs="?")
    ap.add_argument("--file", help="файл с calldata (hex)")
    ap.add_argument("--sig", help="посчитать селектор для сигнатуры")
    ap.add_argument("--json")
    common.add_flag_args(ap)
    args = ap.parse_args()
    common.apply_flag_args(args)

    if args.sig:
        sel = keccak_selector(args.sig)
        if not sel:
            print("[-] нужен pycryptodome (Crypto.Hash.keccak)")
            return
        print(f"{args.sig} -> 0x{sel}")
        return

    raw = args.calldata
    if args.file:
        if not os.path.isfile(args.file):
            print(f"[-] нет файла: {args.file}")
            return
        raw = open(args.file, encoding="utf-8", errors="replace").read()
    if not raw:
        print("[-] нужен calldata или --file/--sig")
        return

    result = decode(raw)
    if not result:
        print("[-] это не hex-calldata")
        return
    print(f"[i] selector: {result['selector']}")
    if result["known"]:
        print(f"[+] функция: {result['signature']}")
    else:
        print("[?] селектор неизвестен — смотри raw_words")
    for key, value in result["args"].items():
        print(f"  {key} = {value}")
    if result["note"]:
        for line in result["note"]:
            print(f"[!] {line}")
    if not result["known"]:
        for i, w in enumerate(result["raw_words"]):
            print(f"  word[{i}] = {w}")

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(result, fh, ensure_ascii=False, indent=1)
        print(f"[i] отчёт: {args.json}")


if __name__ == "__main__":
    main()
