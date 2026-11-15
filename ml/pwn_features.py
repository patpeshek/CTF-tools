"""pwn_features.py — метки для pwn-модели: профиль защит бинарника.

Для pwn первый вопрос всегда один и тот же: «что включено» — NX, PIE, канарейка,
RELRO, статическая ли линковка. От ответа зависит первый приём: переполнение до
ret2win, ret2libc с утечкой, shellcode на исполняемом стеке, ROP по статике.

Всё это считается из заголовков ELF детерминированно (как `checksec`), поэтому
датасет собирается из любого архива без ручной разметки. Модель учится
предсказывать тот же профиль по сырым байтам — это полезно, когда заголовок
покорёжен, файл обрезан или это обёртка вокруг бинарника.

Признаки — те же, что у реверс-модели (`rev_features.hand_features`), плюс
`rev_features.FEATURE_NAMES`.
"""
from __future__ import annotations

import struct

from rev_features import FEATURE_NAMES, byte_hist, byte_ids, hand_features  # noqa: F401

PT_LOAD = 1
PT_INTERP = 3
PT_GNU_STACK = 0x6474E551
PT_GNU_RELRO = 0x6474E552

PF_X = 1

DT_NULL = 0
DT_BIND_NOW = 24
DT_FLAGS = 30
DT_FLAGS_1 = 0x6FFFFFFB
DF_BIND_NOW = 0x8
DF_1_NOW = 0x1

LABELS = [
    "pwn_shellcode",      # стек исполняемый — можно лить шеллкод
    "pwn_ret2win",        # NX, без канарейки, без PIE — классика
    "pwn_ret2libc",       # NX, без канарейки, PIE — нужна утечка адреса
    "pwn_canary_nopie",   # канарейка, без PIE — утечка канарейки
    "pwn_canary_pie",     # канарейка + PIE — самая упорная
    "pwn_static",         # статическая линковка — ROP по своему коду
    "pwn_pe",             # PE: приёмы другие (SEH, DEP)
]


def _elf_phdrs(data: bytes):
    """[(p_type, p_flags)] из таблицы программных заголовков."""
    if data[:4] != b"\x7fELF" or len(data) < 64:
        return []
    is64 = data[4] == 2
    try:
        if is64:
            e_phoff = struct.unpack_from("<Q", data, 0x20)[0]
            e_phentsize = struct.unpack_from("<H", data, 0x36)[0]
            e_phnum = struct.unpack_from("<H", data, 0x38)[0]
        else:
            e_phoff = struct.unpack_from("<I", data, 0x1C)[0]
            e_phentsize = struct.unpack_from("<H", data, 0x2A)[0]
            e_phnum = struct.unpack_from("<H", data, 0x2C)[0]
        if not (0 < e_phnum < 100 and e_phoff and e_phentsize >= 32):
            return []
        out = []
        for i in range(e_phnum):
            off = e_phoff + i * e_phentsize
            p_type = struct.unpack_from("<I", data, off)[0]
            p_flags = struct.unpack_from("<I", data, off + (4 if is64 else 24))[0]
            out.append((p_type, p_flags))
        return out
    except struct.error:
        return []


def _has_bind_now(data: bytes) -> bool:
    """DT_BIND_NOW / DF_BIND_NOW / DF_1_NOW — вторая половина FULL RELRO."""
    for tag, val in _dynamic_entries(data):
        if tag == DT_BIND_NOW:
            return True
        if tag == DT_FLAGS and val & DF_BIND_NOW:
            return True
        if tag == DT_FLAGS_1 and val & DF_1_NOW:
            return True
    return False


def _dynamic_entries(data: bytes):
    """(tag, val) из .dynamic — через program headers PT_DYNAMIC (2)."""
    if data[:4] != b"\x7fELF" or len(data) < 64:
        return []
    is64 = data[4] == 2
    try:
        if is64:
            e_phoff = struct.unpack_from("<Q", data, 0x20)[0]
            e_phentsize = struct.unpack_from("<H", data, 0x36)[0]
            e_phnum = struct.unpack_from("<H", data, 0x38)[0]
        else:
            e_phoff = struct.unpack_from("<I", data, 0x1C)[0]
            e_phentsize = struct.unpack_from("<H", data, 0x2A)[0]
            e_phnum = struct.unpack_from("<H", data, 0x2C)[0]
        for i in range(min(e_phnum, 100)):
            off = e_phoff + i * e_phentsize
            p_type = struct.unpack_from("<I", data, off)[0]
            if p_type != 2:                 # PT_DYNAMIC
                continue
            if is64:
                p_offset = struct.unpack_from("<Q", data, off + 8)[0]
                p_filesz = struct.unpack_from("<Q", data, off + 32)[0]
                step, fmt = 16, "<qQ"
            else:
                p_offset = struct.unpack_from("<I", data, off + 4)[0]
                p_filesz = struct.unpack_from("<I", data, off + 16)[0]
                step, fmt = 8, "<iI"
            out = []
            for k in range(min(p_filesz // step, 400)):
                o = p_offset + k * step
                if o + step > len(data):
                    break
                tag, val = struct.unpack_from(fmt, data, o)
                if tag == DT_NULL:
                    break
                out.append((tag, val))
            return out
    except struct.error:
        return []
    return []


def profile(data: bytes) -> dict:
    """Профиль защит как обычный dict (то же, что печатает pwn/checksec.py)."""
    if data[:2] == b"MZ":
        return {"format": "pe", "nx": None, "pie": None, "canary": None,
                "relro": None, "static": None}
    if data[:4] != b"\x7fELF":
        return {"format": None}
    phdrs = _elf_phdrs(data)
    types = {t for t, _ in phdrs}
    exec_stack = any(t == PT_GNU_STACK and f & PF_X for t, f in phdrs)
    relro = PT_GNU_RELRO in types
    full_relro = relro and _has_bind_now(data)
    e_type = struct.unpack_from("<H", data, 0x10)[0] if len(data) > 18 else 0
    pie = e_type == 3
    static = PT_INTERP not in types
    canary = b"__stack_chk_fail" in data
    # ET_REL (.ko) не имеет PT_GNU_STACK: NX не определена, не выдаём True
    nx = None if PT_GNU_STACK not in types else not exec_stack
    return {
        "format": "elf", "nx": nx, "pie": pie, "canary": canary,
        "relro": "full" if full_relro else ("partial" if relro else "none"),
        "static": static,
    }


def label_of(data: bytes) -> str:
    """Класс задачи pwn — что пробовать первым; '' если это не ELF/PE."""
    p = profile(data)
    fmt = p.get("format")
    if fmt == "pe":
        return "pwn_pe"
    if fmt != "elf":
        return ""
    if p["static"]:
        return "pwn_static"
    if not p["nx"]:
        return "pwn_shellcode"
    if not p["canary"] and not p["pie"]:
        return "pwn_ret2win"
    if not p["canary"]:
        return "pwn_ret2libc"
    if not p["pie"]:
        return "pwn_canary_nopie"
    return "pwn_canary_pie"


def explain(data: bytes) -> str:
    """Человеческая строка для лога: что включено и с чего начинать."""
    p = profile(data)
    if p.get("format") != "elf":
        return "не ELF — профиль защит не считается"
    bits = [f"NX={'on' if p['nx'] else 'OFF'}", f"PIE={'on' if p['pie'] else 'off'}",
            f"canary={'on' if p['canary'] else 'OFF'}", f"RELRO={p['relro']}"]
    return ", ".join(bits)
