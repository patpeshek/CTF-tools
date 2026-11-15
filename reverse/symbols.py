#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
symbols.py — символы и адреса ELF: win-функции, опасные вызовы, /bin/sh.

  python symbols.py ./chall
  python symbols.py ./chall --json

Зачем: в pwn/rev-задаче половина работы — найти, куда прыгать. Если бинарник
не stripped, `ret2win` — это адрес функции `win` из .symtab и ничего больше.
Инструмент печатает готовые пары «имя @ адрес» и смещения строк.

Работает без внешних пакетов: разбирает заголовки ELF вручную.
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
import re
import struct
import sys

SHT_SYMTAB = 2
SHT_DYNSYM = 11
STT_FUNC = 2
STT_OBJECT = 1

# что ищем: имена, по которым сразу видно смысл функции
INTEREST = re.compile(
    r"(?i)^(_*)(win|flag|get_?flag|shell|backdoor|secret|admin|give_?shell|"
    r"print_?flag|cat_?flag|system|execve|mprotect|gets|strcpy|sprintf|"
    r"__stack_chk_fail|main)$")
DANGER = re.compile(r"(?i)^(_*)(gets|strcpy|strcat|sprintf|scanf|printf|system|"
                    r"execve|read|memcpy)$")


def _sections(data: bytes):
    """[(имя, type, addr, offset, size, link, entsize)] из ELF."""
    if data[:4] != b"\x7fELF" or len(data) < 64:
        return []
    is64 = data[4] == 2
    try:
        if is64:
            e_shoff = struct.unpack_from("<Q", data, 0x28)[0]
            e_shentsize = struct.unpack_from("<H", data, 0x3A)[0]
            e_shnum = struct.unpack_from("<H", data, 0x3C)[0]
            e_shstrndx = struct.unpack_from("<H", data, 0x3E)[0]
        else:
            e_shoff = struct.unpack_from("<I", data, 0x20)[0]
            e_shentsize = struct.unpack_from("<H", data, 0x2E)[0]
            e_shnum = struct.unpack_from("<H", data, 0x30)[0]
            e_shstrndx = struct.unpack_from("<H", data, 0x32)[0]
        if not (0 < e_shnum < 400 and e_shoff and e_shstrndx < e_shnum):
            return []
        hdr = e_shoff + e_shstrndx * e_shentsize
        if is64:
            str_off, str_size = struct.unpack_from("<QQ", data, hdr + 0x18)
        else:
            str_off, str_size = struct.unpack_from("<II", data, hdr + 0x10)
        names = data[str_off:str_off + min(str_size, 100000)]
        out = []
        for i in range(e_shnum):
            off = e_shoff + i * e_shentsize
            if is64:
                name_off, sh_type = struct.unpack_from("<II", data, off)
                sh_addr, sh_offset, sh_size = struct.unpack_from("<QQQ", data, off + 0x10)
                sh_link = struct.unpack_from("<I", data, off + 0x28)[0]
                sh_entsize = struct.unpack_from("<Q", data, off + 0x38)[0]
            else:
                name_off, sh_type = struct.unpack_from("<II", data, off)
                sh_addr, sh_offset, sh_size = struct.unpack_from("<III", data, off + 0x0C)
                sh_link = struct.unpack_from("<I", data, off + 0x18)[0]
                sh_entsize = struct.unpack_from("<I", data, off + 0x24)[0]
            end = names.find(b"\x00", name_off)
            nm = names[name_off:end].decode("latin-1") if 0 <= name_off < len(names) else ""
            out.append((nm, sh_type, sh_addr, sh_offset, sh_size, sh_link, sh_entsize))
        return out
    except struct.error:
        return []


def symbols(data: bytes):
    """[(имя, адрес, тип)] из .symtab и .dynsym."""
    secs = _sections(data)
    if not secs:
        return [], "нет таблицы секций (stripped / packed)"
    is64 = data[4] == 2
    out = []
    for nm, sh_type, _addr, sh_offset, sh_size, sh_link, sh_entsize in secs:
        if sh_type not in (SHT_SYMTAB, SHT_DYNSYM):
            continue
        if not (0 < sh_link < len(secs)):
            continue
        str_sh = secs[sh_link]
        strtab = data[str_sh[3]:str_sh[3] + str_sh[4]]
        step = sh_entsize or (24 if is64 else 16)
        for k in range(min(sh_size // step, 20000)):
            off = sh_offset + k * step
            try:
                if is64:
                    st_name = struct.unpack_from("<I", data, off)[0]
                    st_info = data[off + 4]
                    st_value = struct.unpack_from("<Q", data, off + 8)[0]
                else:
                    st_name = struct.unpack_from("<I", data, off)[0]
                    st_value = struct.unpack_from("<I", data, off + 4)[0]
                    st_info = data[off + 12]
            except struct.error:
                break
            if not st_name or st_name >= len(strtab):
                continue
            end = strtab.find(b"\x00", st_name)
            if end < 0:
                continue
            name = strtab[st_name:end].decode("latin-1", "replace")
            if not name:
                continue
            out.append((name, st_value, st_info & 0xF))
    return out, ""


def analyse(path: str):
    with open(path, "rb") as fh:
        data = fh.read(64 * 1024 * 1024)
    syms, note = symbols(data)
    res = {"file": path, "syms": [], "imports": [], "strings": [], "note": note}
    seen = set()
    for name, addr, typ in syms:
        if typ not in (STT_FUNC, STT_OBJECT):
            continue
        if name in seen:
            continue
        if not (INTEREST.match(name) or (DANGER.match(name) and typ == STT_FUNC)):
            continue
        seen.add(name)
        if addr == 0:          # st_value 0 = импорт, адреса в файле нет
            res["imports"].append(name)
        else:
            res["syms"].append({"name": name, "addr": hex(addr), "type": typ})
    # /bin/sh и похожие строки с адресом (для ret2libc: offset binsh)
    secs = _sections(data)
    for pat, label in ((b"/bin/sh\x00", "/bin/sh"), (b"/bin/bash", "/bin/bash")):
        idx = data.find(pat)
        if idx >= 0:
            vaddr = idx
            for _nm, _t, a, o, sz, _l, _e in secs:
                if o <= idx < o + sz:
                    vaddr = a + (idx - o)
                    break
            res["strings"].append({"text": label, "addr": hex(vaddr),
                                   "off": hex(idx)})
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("file")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    try:
        r = analyse(args.file)
    except OSError as exc:
        print(f"[-] {exc}")
        return 2
    if args.json:
        print(json.dumps(r, ensure_ascii=False))
        return 0
    print(f"[+] {args.file}")
    if r["note"]:
        print(f"    {r['note']}")
    wins = [s for s in r["syms"] if re.match(r"(?i)^_*(win|flag|get_?flag|shell|"
                                             r"backdoor|give_?shell|print_?flag|cat_?flag|secret)$",
                                             s["name"])]
    if wins:
        print("[!] похоже на цель: " + ", ".join(f"{s['name']} @ {s['addr']}" for s in wins))
    if r["imports"]:
        print("[i] импорты: " + ", ".join(r["imports"][:14]))
    calls = [s for s in r["syms"] if DANGER.match(s["name"])]
    if calls:
        print("[i] вызовы: " + ", ".join(f"{s['name']}@{s['addr']}" for s in calls[:12]))
    for s in r["strings"]:
        print(f"[i] строка {s['text']} @ {s['addr']} (файл {s['off']})")
    known = {s["name"] for s in wins + calls}
    rest = [s for s in r["syms"] if s["name"] not in known]
    if rest:
        print("[i] прочее: " + ", ".join(f"{s['name']}@{s['addr']}" for s in rest[:10]))
    if not (wins or calls or r["imports"] or r["strings"] or rest):
        print("[-] ничего интересного: stripped или пустая таблица символов")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
