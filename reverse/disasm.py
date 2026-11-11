#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
disasm.py — дизассемблер для реверса без Ghidra (capstone).

  python disasm.py bin --interesting          # только cmp/test/mov imm/lea/call/xor
  python disasm.py bin --all                  # весь .text (осторожно: много)
  python disasm.py bin --grep "cmp|strcmp"    # фильтр по мнемонике/операндам
  python disasm.py bin --around 0x4011a2 -n 40
  python disasm.py bin --strings              # ссылки на строки из .rodata
  python disasm.py bin --func 0x401136       # одна функция: от адреса до ret

Мусорные байты не обрывают листинг (capstone skipdata: строка .byte).

Понимает ELF (x86/x64/arm64) и PE (x86/x64). Пишет vaddr, байты, инструкцию
и, где можно, строку/константу, на которую она ссылается.
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
import struct
import sys

try:
    from capstone import Cs, CS_ARCH_X86, CS_ARCH_ARM64, CS_MODE_32, CS_MODE_64, CS_MODE_ARM
except Exception:
    print("[-] нет capstone: pip install capstone")
    raise SystemExit(1)
try:  # типы операндов: X86_OP_REG=1, X86_OP_IMM=2, X86_OP_MEM=3
    from capstone.x86 import X86_OP_IMM, X86_OP_MEM
except Exception:
    X86_OP_IMM, X86_OP_MEM = 2, 3
try:
    from capstone.arm64 import ARM64_OP_IMM
except Exception:
    ARM64_OP_IMM = None

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import common  # noqa: E402

MACHINE = {0x3E: ("x64", CS_ARCH_X86, CS_MODE_64),
           0x03: ("x86", CS_ARCH_X86, CS_MODE_32),
           0xB7: ("arm64", CS_ARCH_ARM64, CS_MODE_ARM),
           0x28: ("arm", CS_ARCH_ARM64, CS_MODE_ARM)}


def parse_elf(data):
    """Вернуть (arch, sections[(name, addr, off, size)])."""
    if data[:4] != b"\x7fELF":
        return None, []
    is64 = data[4] == 2
    endian = "<" if data[5] == 1 else ">"
    if is64:
        e_shoff = struct.unpack_from(endian + "Q", data, 0x28)[0]
        e_shentsize = struct.unpack_from(endian + "H", data, 0x3A)[0]
        e_shnum = struct.unpack_from(endian + "H", data, 0x3C)[0]
        e_shstrndx = struct.unpack_from(endian + "H", data, 0x3E)[0]
    else:
        e_shoff = struct.unpack_from(endian + "I", data, 0x20)[0]
        e_shentsize = struct.unpack_from(endian + "H", data, 0x2E)[0]
        e_shnum = struct.unpack_from(endian + "H", data, 0x30)[0]
        e_shstrndx = struct.unpack_from(endian + "H", data, 0x32)[0]
    machine = struct.unpack_from(endian + "H", data, 0x12)[0]
    arch = MACHINE.get(machine, ("x64", CS_ARCH_X86, CS_MODE_64))
    sections = []
    if not e_shoff or not e_shnum:
        return arch, sections
    shstr_off = None
    if e_shstrndx != 0:
        base = e_shoff + e_shstrndx * e_shentsize
        if is64:
            shstr_off = struct.unpack_from(endian + "Q", data, base + 0x18)[0]
        else:
            shstr_off = struct.unpack_from(endian + "I", data, base + 0x10)[0]
    for i in range(e_shnum):
        base = e_shoff + i * e_shentsize
        try:
            # Elf64_Shdr: name, type, flags(8), addr@0x10, offset@0x18, size@0x20
            # Elf32_Shdr: name, type, flags(4), addr@0x0C, offset@0x10, size@0x14
            name_off, sh_type = struct.unpack_from(endian + "II", data, base)
            if is64:
                sh_addr, sh_offset, sh_size = struct.unpack_from(endian + "QQQ", data, base + 0x10)
            else:
                sh_addr, sh_offset, sh_size = struct.unpack_from(endian + "III", data, base + 0x0C)
        except struct.error:
            break
        name = ""
        if shstr_off is not None:
            end = data.find(b"\x00", shstr_off + name_off)
            name = data[shstr_off + name_off:end].decode("latin-1", "replace")
        if sh_type != 8:  # не SHT_NOBITS
            sections.append((name, sh_addr, sh_offset, sh_size))
    return arch, sections


def parse_pe(data):
    if data[:2] != b"MZ":
        return None, []
    try:
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        machine = struct.unpack_from("<H", data, e_lfanew + 4)[0]
        nsec = struct.unpack_from("<H", data, e_lfanew + 6)[0]
        opt_size = struct.unpack_from("<H", data, e_lfanew + 20)[0]
        sec0 = e_lfanew + 24 + opt_size
    except struct.error:
        return None, []
    arch = ("x64", CS_ARCH_X86, CS_MODE_64) if machine == 0x8664 else ("x86", CS_ARCH_X86, CS_MODE_32)
    sections = []
    for i in range(nsec):
        b = sec0 + i * 40
        try:
            name = data[b:b + 8].rstrip(b"\x00").decode("latin-1")
            vsize, vaddr, rawsize, rawptr = struct.unpack_from("<IIII", data, b + 8)
        except struct.error:
            break
        sections.append((name, vaddr, rawptr, rawsize))
    return arch, sections


def section_of(sections, va):
    for name, addr, off, size in sections:
        if addr <= va < addr + size:
            return name, off + (va - addr)
    return None, None


def section_at(sections, va):
    """Секция (name, addr, off, size), в которую попадает адрес, с ненулевым addr."""
    for sec in sections:
        name, addr, off, size = sec
        if addr and addr <= va < addr + size:
            return sec
    return None


RET = {"ret", "retn", "retf", "hlt"}


def operand_comment(ins, carch, data, sections):
    """Символ/строка для непосредственного операнда или абсолютного адреса."""
    comment = ""
    for op in ins.operands:
        if carch == CS_ARCH_X86 and op.type == X86_OP_MEM:
            # абсолютный адрес без базы/индекса (i386: mov eax, [0x804a020])
            if not op.mem.base and not op.mem.index and op.mem.disp > 0x1000:
                s = read_cstr(data, sections, op.mem.disp)
                if s and len(s) >= 3:
                    comment += f" ; \"{s}\""
            continue
        imm_type = X86_OP_IMM if carch == CS_ARCH_X86 else ARM64_OP_IMM
        if imm_type is None or op.type != imm_type:
            continue
        val = op.imm & ((1 << 64) - 1)
        if 0x20 <= val < 0x7F:
            comment += f" ; '{chr(val)}'"
        elif val > 0x1000:
            s = read_cstr(data, sections, val)
            if s and len(s) >= 3:
                comment += f" ; \"{s}\""
    return comment


def read_cstr(data, sections, va, limit=120):
    name, off = section_of(sections, va)
    if off is None or off >= len(data):
        return None
    end = data.find(b"\x00", off, off + limit)
    if end < 0:
        end = min(off + limit, len(data))
    raw = data[off:end]
    if len(raw) < 2:
        return None
    if all(32 <= c < 127 or c in (9, 10, 13) for c in raw):
        return raw.decode("latin-1")
    return None


INTERESTING = {"cmp", "test", "xor", "add", "sub", "mov", "movabs", "lea", "call",
               "and", "or", "shl", "shr", "imul", "mul", "div", "idiv", "inc", "dec",
               "adc", "sbb", "loop", "jmp", "jne", "je", "jz", "jnz"}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("file")
    ap.add_argument("--all", action="store_true", help="весь .text")
    ap.add_argument("--interesting", action="store_true", help="только значимые инструкции")
    ap.add_argument("--grep", help="regex по строке инструкции")
    ap.add_argument("--around", type=lambda x: int(x, 0), help="адрес, вокруг которого показать")
    ap.add_argument("-n", "--count", type=int, default=60)
    ap.add_argument("--strings", action="store_true", help="ссылки на строки")
    ap.add_argument("--limit", type=int, default=4000)
    ap.add_argument("--func", type=lambda x: int(x, 0),
                    help="одна функция: от адреса до ret (адрес как в листинге)")
    args = ap.parse_args()

    data = open(args.file, "rb").read()
    arch, sections = parse_elf(data)
    if arch is None:
        arch, sections = parse_pe(data)
    if arch is None:
        print("[-] не ELF и не PE")
        return
    name, carch, cmode = arch
    md = Cs(carch, cmode)
    md.detail = True
    md.skipdata = True  # мусорный байт не обрывает листинг: .byte и дальше

    text = None
    for want in (".text", "text", ".init", ".plt"):
        for sname, addr, off, size in sections:
            if sname == want and size > 0:
                text = (sname, addr, off, size)
                break
        if text:
            break
    if text is None:
        name0, addr, off, size = max(sections, key=lambda s: s[3]) if sections else (None, 0, 0, 0)
        text = (name0 or "?", addr, off, size)
    if args.func is not None:
        sec = section_at(sections, args.func)
        if sec is None:
            print(f"[-] адрес 0x{args.func:x} не попадает ни в одну секцию")
            return
        sname, addr, off, size = sec
        delta = args.func - addr
        text = (sname, args.func, off + delta, size - delta)

    sname, base, off, size = text
    what = f"функция @0x{base:x} ({sname})" if args.func is not None else f"{sname} @0x{base:x}"
    print(f"[+] {os.path.basename(args.file)}: {name}, {what}, {size} b")
    code = data[off:off + size]
    if args.around:
        start = max(0, (args.around - base) - args.count * 4)
        code = code[start:]
        base += start

    shown = 0
    for ins in md.disasm(code, base):
        txt = f"{ins.mnemonic} {ins.op_str}".strip()
        keep = args.all or bool(args.around) or args.func is not None
        if args.interesting:
            keep = ins.mnemonic in INTERESTING
        if args.grep and re.search(args.grep, txt, re.I):
            keep = True
        comment = ""
        # RIP-relative ссылки: [rip + 0xNN] -> адрес = ins.address + size + disp
        mrip = re.search(r"\[rip ([+-]) 0x([0-9a-fA-F]+)\]", ins.op_str)
        if mrip:
            delta = int(mrip.group(2), 16) * (1 if mrip.group(1) == "+" else -1)
            target = ins.address + ins.size + delta
            s = read_cstr(data, sections, target)
            if s and len(s) >= 3:
                comment += f" ; \"{s}\""
        if not comment and ins.id != 0:  # id 0 — пропущенный байт (.byte)
            comment = operand_comment(ins, carch, data, sections)
        if args.strings:
            keep = bool(comment)
        if not keep:
            continue
        print(f"  0x{ins.address:08x}  {ins.bytes.hex():<16} {txt}{comment}")
        shown += 1
        if shown >= args.limit:
            print("   ... (лимит)")
            break
        if args.func is not None and ins.mnemonic in RET:
            break
    if shown == 0:
        print("[-] ничего под фильтр не попало")


if __name__ == "__main__":
    try:
        main()
    except (FileNotFoundError, IsADirectoryError, PermissionError) as e:
        print(f"[-] не могу открыть: {getattr(e, 'filename', None) or e}")
    except BrokenPipeError:
        pass
    except KeyboardInterrupt:
        print("\n[-] прервано")
