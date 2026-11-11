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

CHANNELS = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}       # color type -> каналов
ADAM7 = [(0, 0, 8, 8), (4, 0, 8, 8), (0, 4, 4, 8), (2, 0, 4, 4),
         (0, 2, 2, 4), (1, 0, 2, 2), (0, 1, 1, 2)]
MAX_DIM = 1 << 16                                 # перебор ширины/высоты по CRC


def raw_size(w, h, depth, color, interlace):
    """Сколько байт должно получиться из IDAT после inflate (с байтами фильтра)."""
    bpp = CHANNELS.get(color, 0) * depth
    if not bpp:
        return None
    if not interlace:
        return h * (1 + (w * bpp + 7) // 8)
    total = 0
    for x0, y0, dx, dy in ADAM7:
        pw, ph = (w - x0 + dx - 1) // dx, (h - y0 + dy - 1) // dy
        if pw > 0 and ph > 0:
            total += ph * (1 + (pw * bpp + 7) // 8)
    return total


def inflated_size(z: bytes, cap=256 << 20):
    """Длина распакованного zlib-потока без хранения целиком; None — битый/больше cap."""
    d = zlib.decompressobj()
    total = 0
    try:
        while z:
            total += len(d.decompress(z, 1 << 20))
            z = d.unconsumed_tail
            if total > cap:
                return None
        total += len(d.flush())
    except zlib.error:
        return None
    return total


def dims_from_crc(ihdr: bytes, crc: int):
    """Все (w, h) из 1..MAX_DIM, при которых CRC IHDR совпадает с записанным.

    CRC32 аффинна для сообщений одной длины:
    crc(w, h) = crc(w, 0) ^ crc(0, h) ^ crc(0, 0) — поэтому вместо 2^32
    вариантов хватает словаря по ширинам и прохода по высотам.
    """
    rest = ihdr[8:13]
    zero = b"\x00\x00\x00\x00"
    c00 = zlib.crc32(b"IHDR" + zero + zero + rest)
    by_w = {}
    for w in range(1, MAX_DIM + 1):
        by_w[zlib.crc32(b"IHDR" + w.to_bytes(4, "big") + zero + rest) ^ c00 ^ crc] = w
    found = []
    for h in range(1, MAX_DIM + 1):
        w = by_w.get(zlib.crc32(b"IHDR" + zero + h.to_bytes(4, "big") + rest))
        if w is not None:
            found.append((w, h))
    return found


def pick_dims(ihdr: bytes, crc: int, idat: bytes):
    """Настоящие (w, h) по CRC; при нескольких кандидатах сверяем с размером IDAT."""
    ow, oh = struct.unpack(">II", ihdr[:8])
    depth, color, interlace = ihdr[8], ihdr[9], ihdr[12]
    cands = dims_from_crc(ihdr, crc)
    if not cands:
        return None
    raw = inflated_size(idat) if idat else None
    if raw is not None:
        good = [c for c in cands if raw_size(*c, depth, color, interlace) == raw]
        if good:
            cands = good
        elif raw_size(ow, oh, depth, color, interlace) == raw:
            return None          # размер и так сходится с IDAT — испорчен сам CRC
    cands.sort(key=lambda c: (c[0] != ow and c[1] != oh, c[0] * c[1]))
    return cands[0]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("file")
    ap.add_argument("--extract", help="папка для чанков")
    ap.add_argument("--text-only", action="store_true")
    ap.add_argument("--fix", help="записать PNG: размер IHDR подобрать по его CRC, "
                                  "остальные битые CRC пересчитать")
    args = ap.parse_args()

    data = open(args.file, "rb").read()
    if not data.startswith(SIG):
        print("[-] это не PNG")
        return

    i = len(SIG)
    n = 0
    bad_crc = 0
    rebuilt = bytearray(SIG)
    ihdr_bad = None          # (смещение данных IHDR в rebuilt, данные, записанный CRC)
    idat = []
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
            if stored != calc and len(cdata) == 13:
                ihdr_bad = (len(rebuilt) + 8, cdata, stored)
        elif ctype == b"IDAT":
            idat.append(cdata)
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

    if ihdr_bad:
        # частый трюк: поменяли ширину/высоту, CRC оставили старым —
        # тогда настоящий размер восстанавливается из CRC
        off, ihdr, stored = ihdr_bad
        dims = pick_dims(ihdr, stored, b"".join(idat))
        if dims:
            ow, oh = struct.unpack(">II", ihdr[:8])
            print(f"[+] IHDR: CRC сходится при размере {dims[0]}x{dims[1]} (в файле {ow}x{oh})")
            rebuilt[off:off + 8] = struct.pack(">II", *dims)
            rebuilt[off + 13:off + 17] = struct.pack(">I", stored)
        else:
            print("[!] IHDR: размер по CRC не подобрался — для --fix CRC будет пересчитан")

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
