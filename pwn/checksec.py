#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
checksec.py — защиты бинарника без pwntools: ELF и PE.

  python checksec.py ./bin
  python checksec.py ./bin --json
  python checksec.py C:\\Windows\\System32\\notepad.exe

ELF: Arch, PIE, NX, Canary, RELRO, Fortify.
PE:  Arch, ASLR, NX, CFG, DLL/EXE.
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
import struct


def elf_info(data: bytes):
    if len(data) < 64:
        return {"error": "слишком короткий файл"}
    ei_class, ei_data = data[4], data[5]
    bits = 64 if ei_class == 2 else 32
    endian = "<" if ei_data == 1 else ">"
    machine = struct.unpack_from(endian + "H", data, 18)[0]
    e_type = struct.unpack_from(endian + "H", data, 16)[0]
    arch = {0x3E: "x86-64", 0x03: "i386", 0x28: "ARM", 0xB7: "AArch64",
            0xF3: "RISC-V"}.get(machine, hex(machine))

    if bits == 64:
        e_phoff = struct.unpack_from(endian + "Q", data, 32)[0]
        e_phentsize = struct.unpack_from(endian + "H", data, 54)[0]
        e_phnum = struct.unpack_from(endian + "H", data, 56)[0]
    else:
        e_phoff = struct.unpack_from(endian + "I", data, 28)[0]
        e_phentsize = struct.unpack_from(endian + "H", data, 42)[0]
        e_phnum = struct.unpack_from(endian + "H", data, 44)[0]

    flags = []
    nx = None
    relro = False
    interp = False
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        if off + e_phentsize > len(data):
            break
        p_type = struct.unpack_from(endian + "I", data, off)[0]
        if bits == 64:
            p_flags = struct.unpack_from(endian + "I", data, off + 4)[0]
        else:
            p_flags = struct.unpack_from(endian + "I", data, off + 24)[0]
        if p_type == 0x6474E551:      # GNU_STACK
            nx = not bool(p_flags & 0x1)
        elif p_type == 0x6474E552:    # GNU_RELRO
            relro = True
        elif p_type == 3:             # PT_INTERP
            interp = True

    text = data
    canary = b"__stack_chk_fail" in text
    fortify = b"_chk" in text
    bind_now = (b"BIND_NOW" in text) or (b"FLAGS_1" in text)

    pie = (e_type == 3 and interp) or b"DF_1_PIE" in text or b"PIE" in text
    relro_s = "full" if (relro and bind_now) else ("partial" if relro else "no")

    return {
        "format": "ELF",
        "arch": arch,
        "bits": bits,
        "endian": "little" if endian == "<" else "big",
        "type": {1: "ET_REL", 2: "ET_EXEC", 3: "ET_DYN", 4: "ET_CORE"}.get(e_type, str(e_type)),
        "PIE": bool(pie),
        "NX": nx,
        "Canary": canary,
        "RELRO": relro_s,
        "Fortify": fortify,
    }


def pe_info(data: bytes):
    if len(data) < 0x40 or data[:2] != b"MZ":
        return {"error": "не PE"}
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        return {"error": "нет PE-подписи"}
    coff = e_lfanew + 4
    machine, nsect = struct.unpack_from("<HH", data, coff)
    opt_size = struct.unpack_from("<H", data, coff + 16)[0]
    opt = coff + 20
    magic = struct.unpack_from("<H", data, opt)[0]
    bits = 64 if magic == 0x20B else 32
    characteristics = struct.unpack_from("<H", data, coff + 18)[0]
    dll = bool(characteristics & 0x2000)
    dllchar = struct.unpack_from("<H", data, opt + 70)[0] if opt_size >= 72 else 0

    arch = {0x14C: "i386", 0x8664: "x86-64", 0xAA64: "AArch64",
            0x1C0: "ARM", 0x1C4: "ARMv7"}.get(machine, hex(machine))
    return {
        "format": "PE",
        "arch": arch,
        "bits": bits,
        "type": "DLL" if dll else "EXE",
        "ASLR": bool(dllchar & 0x0040),
        "NX": bool(dllchar & 0x0100),
        "CFG": bool(dllchar & 0x4000),
        "HighEntropyVA": bool(dllchar & 0x0080),
        "sections": nsect,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("file")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    data = open(args.file, "rb").read()
    if data[:4] == b"\x7fELF":
        info = elf_info(data)
    elif data[:2] == b"MZ":
        info = pe_info(data)
    else:
        info = {"error": "ни ELF, ни PE"}

    if args.json:
        print(json.dumps(info, ensure_ascii=False, indent=2))
        return
    print(f"[+] {args.file}")
    for k, v in info.items():
        print(f"    {k:14s} {v}")


if __name__ == "__main__":
    try:
        main()
    except (FileNotFoundError, IsADirectoryError, PermissionError) as e:
        print(f"[-] не могу открыть: {getattr(e, 'filename', None) or e}")
    except BrokenPipeError:
        pass
    except KeyboardInterrupt:
        print("\n[-] прервано")
