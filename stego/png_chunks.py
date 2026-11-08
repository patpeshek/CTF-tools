#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
png_chunks.py — разбор PNG по чанкам: текст, zlib-текст, хвост после IEND.

  python png_chunks.py pic.png
  python png_chunks.py pic.png --extract out
  python png_chunks.py pic.png --text-only

Ищет: tEXt, zTXt, iTXt, нестандартные чанки, данные после IEND.
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
import os
import struct
import zlib

SIG = b"\x89PNG\r\n\x1a\n"
KNOWN = {b"IHDR", b"PLTE", b"IDAT", b"IEND", b"tEXt", b"zTXt", b"iTXt",
         b"pHYs", b"tIME", b"gAMA", b"cHRM", b"sRGB", b"iCCP", b"bKGD",
         b"hIST", b"tRNS", b"sBIT", b"eXIf", b"acTL", b"fcTL", b"fdAT"}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("file")
    ap.add_argument("--extract", help="папка для чанков")
    ap.add_argument("--text-only", action="store_true")
    ap.add_argument("--fix", help="записать PNG с пересчитанными CRC")
    args = ap.parse_args()

    data = open(args.file, "rb").read()
    if not data.startswith(SIG):
        print("[-] это не PNG")
        return

    i = len(SIG)
    n = 0
    bad_crc = 0
    rebuilt = bytearray(SIG)
    while i + 8 <= len(data):
        length, ctype = struct.unpack(">I4s", data[i:i + 8])
        cdata = data[i + 8:i + 8 + length]
        crc = data[i + 8 + length:i + 12 + length]
        name = ctype.decode("latin-1", "replace")
        n += 1

        if len(cdata) < length or len(crc) < 4:
            print(f"{n:3d}. {name:8s} len={length} — [!] файл обрезан")
            break

        stored = struct.unpack(">I", crc)[0]
        calc = zlib.crc32(ctype + cdata) & 0xFFFFFFFF
        if stored != calc:
            bad_crc += 1
        if not args.text_only or ctype in (b"tEXt", b"zTXt", b"iTXt"):
            flag = "" if stored == calc else f"  [!] CRC {stored:08x} != {calc:08x}"
            print(f"{n:3d}. {name:8s} len={length}{flag}")

        if ctype == b"IHDR" and len(cdata) >= 8:
            w, h = struct.unpack(">II", cdata[:8])
            depth, color = cdata[8], cdata[9]
            print(f"     IHDR {w}x{h}, depth={depth}, color={color}")
        elif ctype == b"tEXt":
            try:
                k, v = cdata.split(b"\x00", 1)
                print(f"     tEXt {k.decode()!r}: {v.decode('latin-1')[:200]!r}")
            except ValueError:
                pass
        elif ctype == b"zTXt":
            try:
                k, rest = cdata.split(b"\x00", 1)
                v = zlib.decompress(rest[1:])
                print(f"     zTXt {k.decode()!r}: {v.decode('utf-8', 'replace')[:300]!r}")
            except Exception as e:
                print("     zTXt error:", e)
        elif ctype == b"iTXt":
            try:
                k, rest = cdata.split(b"\x00", 1)
                comp_flag = rest[0]
                rest = rest[2:]
                lang, rest = rest.split(b"\x00", 1)
                trans, rest = rest.split(b"\x00", 1)
                v = zlib.decompress(rest) if comp_flag else rest
                print(f"     iTXt {k.decode()!r}: {v.decode('utf-8', 'replace')[:300]!r}")
            except Exception as e:
                print("     iTXt error:", e)
        elif ctype not in KNOWN and ctype[:1].isupper():
            print(f"     [!] незнакомый критичный чанк {name!r} — смотри данные")

        if args.extract:
            os.makedirs(args.extract, exist_ok=True)
            path = os.path.join(args.extract, f"{n:03d}_{name}.bin")
            open(path, "wb").write(cdata)

        rebuilt += struct.pack(">I", length) + ctype + cdata + struct.pack(">I", calc)
        if ctype == b"IEND":
            i += 12 + length
            break
        i += 12 + length

    if bad_crc:
        print(f"[!] чанков с битым CRC: {bad_crc}")
        if args.fix:
            with open(args.fix, "wb") as f:
                f.write(rebuilt + data[i:])
            print(f"[+] исправлено: {args.fix}")
        else:
            print("    починить: --fix fixed.png (или pngcsum/pngcheck)")
    else:
        print("[+] CRC у всех чанков совпадает")

    tail = data[i:]
    print(f"[+] после IEND: {len(tail)} байт")
    if tail:
        print("    hex:", tail[:64].hex())
        print("    txt:", "".join(chr(c) if 32 <= c < 127 else "." for c in tail[:100]))
        if args.extract:
            os.makedirs(args.extract, exist_ok=True)
            open(os.path.join(args.extract, "tail.bin"), "wb").write(tail)


if __name__ == "__main__":
    try:
        main()
    except (FileNotFoundError, IsADirectoryError, PermissionError) as e:
        print(f"[-] не могу открыть: {getattr(e, 'filename', None) or e}")
    except BrokenPipeError:
        pass
    except KeyboardInterrupt:
        print("\n[-] прервано")
