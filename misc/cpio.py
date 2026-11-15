#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
cpio.py — распаковать cpio/initramfs (newc, crc, odc) и поискать флаги.

  python cpio.py rootfs.cpio --out C:\\Temp\\cpio_out
  python cpio.py rootfs.cpio --list
  python cpio.py rootfs.cpio --grep

Зачем: в задачах про Linux/initramfs флаг лежит внутри `rootfs.cpio`
(`070701`), а кит такие архивы не открывал — провал на ровном месте.
Формат простой: 110-байтный ASCII-заголовок, имя, данные с выравниванием 4.
"""
from __future__ import annotations

try:
    import sys as _sys
    for _stream in (_sys.stdout, _sys.stderr):
        _stream.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

import argparse
import os
import re
import sys

FLAG_RX = re.compile(rb"[A-Za-z0-9_]{2,20}\{[ -~]{3,80}\}")
MAGIC_NEWC = b"070701"
MAGIC_CRC = b"070702"
MAGIC_ODC = b"070707"


def parse_newc(data: bytes):
    """[(имя, mode, содержимое)] из newc/crc cpio."""
    out = []
    pos = 0
    while pos + 110 <= len(data):
        if data[pos:pos + 6] not in (MAGIC_NEWC, MAGIC_CRC):
            if data[pos:pos + 6] == MAGIC_ODC:
                break
            nxt = data.find(MAGIC_NEWC, pos + 1)
            if nxt < 0:
                break
            pos = nxt
            continue
        try:
            fields = [int(data[pos + 6 + i * 8: pos + 14 + i * 8], 16)
                      for i in range(13)]
        except ValueError:
            break
        mode, filesize, namesize = fields[1], fields[6], fields[11]
        name_start = pos + 110
        name = data[name_start:name_start + namesize].rstrip(b"\x00").decode(
            "utf-8", "replace")
        data_start = name_start + namesize
        data_start += (-data_start) % 4
        content = data[data_start:data_start + filesize]
        out.append((name, mode, content))
        pos = data_start + filesize
        pos += (-pos) % 4
        if name == "TRAILER!!!":
            break
    return out


def safe_name(name: str) -> str:
    name = name.replace("\\", "/").lstrip("/")
    parts = [p for p in name.split("/") if p not in ("", ".", "..")]
    return "/".join(parts) or "file"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("file")
    ap.add_argument("--out", default=None)
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--grep", action="store_true", help="искать флаги в содержимом")
    ap.add_argument("--max-files", type=int, default=4000)
    args = ap.parse_args()

    with open(args.file, "rb") as fh:
        data = fh.read()
    if data[:6] not in (MAGIC_NEWC, MAGIC_CRC, MAGIC_ODC):
        print("[-] не cpio (нет 070701/070702/070707)")
        return 2
    if data[:6] == MAGIC_ODC:
        print("[-] формат odc (070707) пока не поддерживается")
        return 2

    entries = parse_newc(data)
    files = [(n, m, c) for n, m, c in entries if not n.endswith("/")]
    print(f"[+] {args.file}: файлов {len(files)} (всего записей {len(entries)})")

    if args.list:
        for n, m, c in files[:60]:
            print(f"    {len(c):9d}  {oct(m)[-4:]}  {n}")
        if len(files) > 60:
            print(f"    … ещё {len(files) - 60}")

    if args.grep:
        found = 0
        for n, m, c in files:
            for hit in FLAG_RX.finditer(c):
                print(f"[!] {n}: {hit.group(0).decode('latin-1')[:80]}")
                found += 1
        if not found:
            print("[-] флагов в содержимом нет")

    if args.out:
        os.makedirs(args.out, exist_ok=True)
        written = 0
        for n, m, c in files[:args.max_files]:
            dst = os.path.join(args.out, safe_name(n))
            try:
                os.makedirs(os.path.dirname(dst), exist_ok=True)
                with open(dst, "wb") as fh:
                    fh.write(c)
                written += 1
            except OSError:
                continue
        print(f"[+] распаковано {written} → {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
