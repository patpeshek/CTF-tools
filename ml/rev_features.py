"""rev_features.py — признаки и метки специально для реверса.

Обычный роутер отвечает «это elf». Для реверса это бесполезно: важно **что
за бинарник** — на Go, на Rust, упакован UPX, .NET, статический или
динамический, со символами или stripped. От этого зависит первый инструмент:
`upx -d`, `go_resolve`, ILSpy, `objdump`, Ghidra.

Метка выводится детерминированно из самого файла (секции, интерпретатор,
строки, заголовки), поэтому датасет собирается из любого архива без разметки
руками.
"""
from __future__ import annotations

import re
import struct

import numpy as np

# ---------------------------------------------------------------- метки -----
GO_MARKERS = (b"Go build ID", b"go1.", b"runtime.main", b"golang")
RUST_MARKERS = (b"rustc", b"core::panicking", b"rust_begin_unwind", b"cargo")
DOTNET_MARKERS = (b"mscoree.dll", b"BSJB", b"_CorExeMain")
PACK_MARKERS = (b"UPX!", b"UPX0", b"UPX1", b"$Info: This file is packed")


def _elf_sections(data: bytes) -> list[str]:
    """Имена секций из заголовка ELF (без внешних библиотек)."""
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
        if not (0 < e_shnum < 200 and e_shoff and e_shstrndx < e_shnum):
            return []
        base = e_shoff + e_shstrndx * e_shentsize
        if is64:
            str_off = struct.unpack_from("<Q", data, base + 0x18)[0]
            str_size = struct.unpack_from("<Q", data, base + 0x20)[0]
        else:
            str_off = struct.unpack_from("<I", data, base + 0x10)[0]
            str_size = struct.unpack_from("<I", data, base + 0x14)[0]
        names_blob = data[str_off:str_off + min(str_size, 20000)]
        out = []
        for i in range(e_shnum):
            off = e_shoff + i * e_shentsize
            if is64:
                name_off = struct.unpack_from("<I", data, off)[0]
            else:
                name_off = struct.unpack_from("<I", data, off)[0]
            end = names_blob.find(b"\x00", name_off)
            if name_off < len(names_blob) and end > name_off:
                out.append(names_blob[name_off:end].decode("latin-1"))
        return out
    except struct.error:
        return []


def _elf_phdrs(data: bytes) -> list[tuple[int, int]]:
    """[(p_type, p_flags)] из таблицы программных заголовков ELF."""
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


def _pe_has_dotnet(data: bytes) -> bool:
    if data[:2] != b"MZ":
        return False
    try:
        pe_off = struct.unpack_from("<I", data, 0x3C)[0]
        if data[pe_off:pe_off + 4] != b"PE\x00\x00":
            return False
        opt_magic = struct.unpack_from("<H", data, pe_off + 24)[0]
        if opt_magic == 0x20B:      # PE32+
            dir_off = pe_off + 24 + 112
        else:                        # PE32
            dir_off = pe_off + 24 + 96
        clr_rva, clr_size = struct.unpack_from("<II", data, dir_off + 14 * 8)
        return clr_rva != 0 and clr_size != 0
    except (struct.error, IndexError):
        return False


def label_of(data: bytes) -> str:
    """Семейство бинарника; '' если это не ELF/PE."""
    head = data[:64]
    if head[:4] == b"\x7fELF":
        secs = _elf_sections(data)
        blob = data[:4_000_000]
        if any(m in blob[:300000] for m in PACK_MARKERS) or any(
                s.startswith("UPX") for s in secs):
            return "elf_packed"
        if any(m in blob for m in GO_MARKERS):
            return "elf_go"
        if any(m in blob for m in RUST_MARKERS):
            return "elf_rust"
        has_interp = ".interp" in secs or b"/lib64/ld-linux" in blob[:100000]
        has_symtab = ".symtab" in secs or ".debug_info" in secs
        e_type = struct.unpack_from("<H", data, 0x10)[0] if len(data) > 18 else 0
        # ET_DYN без интерпретатора — это .so (libc и т.п.), а не «stripped exe».
        # Без этого класса весь архив схлопывался в 'elf_stripped' (1900 из 2300).
        if e_type == 3 and not has_interp:
            return "elf_shared"
        if not secs:                     # заголовок не разобрался — stripped
            return "elf_stripped"
        if has_interp and has_symtab:
            return "elf_dynamic"
        if has_interp:
            return "elf_stripped"
        if has_symtab:
            return "elf_static"
        return "elf_stripped"
    if head[:2] == b"MZ":
        blob = data[:4_000_000]
        if _pe_has_dotnet(data) or any(m in blob for m in DOTNET_MARKERS):
            return "pe_dotnet"
        if any(m in blob[:300000] for m in PACK_MARKERS):
            return "pe_packed"
        return "pe_native"
    return ""


LABELS = ["elf_go", "elf_rust", "elf_packed", "elf_dynamic", "elf_static",
          "elf_stripped", "elf_shared", "pe_native", "pe_dotnet", "pe_packed"]

# ------------------------------------------------------------ признаки -----
SEC_RE = re.compile(rb"\.(text|data|rodata|bss|symtab|debug_info|interp|plt\w*|got\w*)")


def hand_features(data: bytes) -> np.ndarray:
    n = max(1, len(data))
    chunk = data[:65536]
    secs = _elf_sections(data) if data[:4] == b"\x7fELF" else []
    blob = data[:4_000_000]

    def has(*markers):
        return 1.0 if any(m in blob for m in markers) else 0.0

    printable = sum(1 for b in chunk if 32 <= b <= 126 or b in (9, 10, 13)) / max(1, len(chunk))
    zero = chunk.count(b"\x00") / max(1, len(chunk))
    # энтропия по первым 64 КБ
    counts = np.bincount(np.frombuffer(chunk, dtype=np.uint8), minlength=256)
    p = counts[counts > 0] / max(1, len(chunk))
    entropy = float(-(p * np.log2(p)).sum()) if len(p) else 0.0
    strings = len(re.findall(rb"[\x20-\x7e]{6,}", chunk))

    # --- маркеры защит: без них pwn-модель путала ret2libc и canary ---
    try:
        phdrs = _elf_phdrs(data) if data[:4] == b"\x7fELF" else []
    except Exception:
        phdrs = []
    gnu_stack = [f for t, f in phdrs if t == 0x6474E551]
    has_gnu_stack = 1.0 if gnu_stack else 0.0
    stack_nx = 1.0 if (gnu_stack and not (gnu_stack[0] & 1)) else 0.0
    e_type = struct.unpack_from("<H", data, 0x10)[0] if len(data) > 18 else 0

    vec = [
        np.log1p(len(data)),
        entropy,
        printable,
        zero,
        np.log1p(len(secs)),
        np.log1p(strings),
        1.0 if ".symtab" in secs else 0.0,
        1.0 if ".debug_info" in secs else 0.0,
        1.0 if ".interp" in secs else 0.0,
        1.0 if ".plt" in " ".join(secs) else 0.0,
        1.0 if ".got" in " ".join(secs) else 0.0,
        1.0 if data[:4] == b"\x7fELF" else 0.0,
        1.0 if data[:2] == b"MZ" else 0.0,
        has(*GO_MARKERS),
        has(*RUST_MARKERS),
        has(*PACK_MARKERS),
        has(*DOTNET_MARKERS),
        has(b"/lib64/ld-linux", b"/lib/ld-musl", b"ld-linux"),
        1.0 if b"UPX" in chunk[:4096] else 0.0,
        data[4] / 2.0 if len(data) > 4 else 0.0,        # 32/64 бит
        (data[18] if len(data) > 18 else 0) / 255.0,    # машина (младший байт)
        float(sum(len(s) for s in secs) / max(1, len(secs))),  # средняя длина имени
        1.0 if b"__stack_chk_fail" in blob else 0.0,   # канарейка
        stack_nx,                                      # NX стека (1 = включён)
        has_gnu_stack,                                 # есть PT_GNU_STACK
        1.0 if e_type == 3 else 0.0,                   # ET_DYN (PIE/so)
    ]
    return np.asarray(vec, dtype=np.float32)


FEATURE_NAMES = [
    "size_log", "entropy", "printable", "zero_frac", "sections_log",
    "strings_log", "has_symtab", "has_debug", "has_interp", "has_plt",
    "has_got", "is_elf", "is_pe", "mark_go", "mark_rust", "mark_pack",
    "mark_dotnet", "mark_ld", "upx_head", "elf_class", "elf_machine",
    "avg_secname", "mark_canary", "stack_nx", "has_gnu_stack", "et_dyn",
]


def byte_hist(data: bytes) -> np.ndarray:
    counts = np.bincount(np.frombuffer(data[:65536], dtype=np.uint8),
                         minlength=256).astype(np.float32)
    if counts.sum():
        counts /= counts.sum()
    return np.log1p(counts * 1000.0)


def byte_ids(data: bytes, max_len: int = 256) -> np.ndarray:
    out = np.zeros(max_len, dtype=np.int16)
    chunk = data[:max_len]
    out[:len(chunk)] = np.frombuffer(chunk, dtype=np.uint8).astype(np.int16) + 1
    return out
