#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
megarev.py — «мега-реверс» для бинарника/файла: что это, чем упаковано,
какие строки/ключи/вложенные файлы внутри, и перебор шифров по найденным блобам.

  python megarev.py --file ./bin
  python megarev.py --file ./app.exe --deep
  python megarev.py --dir dump
  python megarev.py --file ./bin --out carved

Что делает:
  * тип (ELF/PE/Mach-O/pyc/PYZ/APK/Java/.NET/Go/Rust/Electron), защиты (ELF/PE);
  * упаковщики: UPX, PyInstaller, pyarmor, Nuitka, py2exe, .NET, Electron;
  * секции/оверлей: хвост после образа, высокая энтропия (шифр/пакер);
  * строки: ASCII/UTF-16, интересные ключи, URL, флаги, base64/hex;
  * pyc: константы и дизассемблер (без выполнения);
  * вложенные файлы по сигнатурам (PNG/ZIP/PDF/ELF/…), можно вырезать;
  * XOR-скан и перебор ключей из строк по найденным блобам (XOR/RC4/AES/…).
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
import hashlib
import io
import json
import math
import marshal
import os
import re
import struct
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
for sub in ("", "..", "../crypto", "../pwn", "../stego"):
    sys.path.insert(0, os.path.abspath(os.path.join(HERE, sub)))
sys.path.insert(0, os.path.abspath(os.path.join(HERE, "..")))

import common          # noqa: E402
import autocrack as ac  # noqa: E402
import megacrack as mg  # noqa: E402
import checksec         # noqa: E402

SIGS = [
    (b"\x89PNG\r\n\x1a\n", "PNG", ".png"),
    (b"\xff\xd8\xff", "JPEG", ".jpg"),
    (b"GIF89a", "GIF", ".gif"),
    (b"PK\x03\x04", "ZIP", ".zip"),
    (b"\x1f\x8b\x08", "GZIP", ".gz"),
    (b"7z\xbc\xaf\x27\x1c", "7Z", ".7z"),
    (b"Rar!\x1a\x07", "RAR", ".rar"),
    (b"%PDF", "PDF", ".pdf"),
    (b"\x7fELF", "ELF", ".elf"),
    (b"SQLite format 3\x00", "SQLite", ".sqlite"),
    (b"\x00\x00\x01\x00", "ICO", ".ico"),
]

MARKERS = [
    (b"UPX!", "UPX", "upx -d file"),
    (b"MEI\x0c\x0b\x0a\x0b\x0e", "PyInstaller", "pyinstxtractor, затем pycdc"),
    (b"pyarmor_runtime", "pyarmor", "дамп памяти процесса, ищи pyarmor_runtime"),
    (b"PYZ-00.pyz", "PyInstaller PYZ", "pyinstxtractor"),
    (b"Nuitka", "Nuitka", "Ghidra/IDA"),
    (b"py2exe", "py2exe", "распакуй и pycdc"),
    (b"BSJB", ".NET", "dnSpy / ILSpy"),
    (b"mscoree", ".NET", "dnSpy / ILSpy"),
    (b"Electron", "Electron", "asar extract app.asar"),
    (b"classes.dex", "Android/Java", "jadx / apktool"),
    (b"go1.", "Go", "GoReSym, затем Ghidra"),
    (b"rustc", "Rust", "Ghidra, ищи строки и сравнения"),
    (b"This program cannot be run in DOS mode", "PE", "-"),
]

KEYWORDS = ("flag", "ctf", "key", "pass", "secret", "correct", "wrong", "license",
            "serial", "token", "aes", "rc4", "base64", "http", "admin", "root")
SECRET_WORDS = ("pin", "password", "passwd", "pass", "key", "code", "token",
                "secret", "unlock", "serial", "license")


def entropy(b: bytes) -> float:
    if not b:
        return 0.0
    counts = [0] * 256
    for c in b:
        counts[c] += 1
    n = len(b)
    return -sum((c / n) * math.log2(c / n) for c in counts if c)


def utf16_strings(data: bytes, minlen=4, limit=200):
    out = []
    i = 0
    while i + 1 < len(data):
        start = None
        chars = []
        j = i
        while j + 1 < len(data):
            c = data[j]
            if 32 <= c < 127 and data[j + 1] == 0:
                if start is None:
                    start = j
                chars.append(chr(c))
                j += 2
            else:
                break
        if start is not None and len(chars) >= minlen:
            out.append((start, "".join(chars)))
            i = j
            if len(out) >= limit:
                break
        else:
            i += 1
    return out


def section_end(data: bytes):
    """Конец образа: для ELF/PE — максимальный конец секции."""
    try:
        if data[:4] == b"\x7fELF":
            cls, endian = data[4], data[5]
            e = "<" if endian == 1 else ">"
            if cls == 2:
                shoff = struct.unpack_from(e + "Q", data, 40)[0]
                shentsize = struct.unpack_from(e + "H", data, 58)[0]
                shnum = struct.unpack_from(e + "H", data, 60)[0]
                end = 0
                for i in range(shnum):
                    off = shoff + i * shentsize
                    if off + 32 > len(data):
                        break
                    sh_off = struct.unpack_from(e + "Q", data, off + 24)[0]
                    sh_size = struct.unpack_from(e + "Q", data, off + 32)[0]
                    end = max(end, sh_off + sh_size)
                return end
            else:
                shoff = struct.unpack_from(e + "I", data, 32)[0]
                shentsize = struct.unpack_from(e + "H", data, 46)[0]
                shnum = struct.unpack_from(e + "H", data, 48)[0]
                end = 0
                for i in range(shnum):
                    off = shoff + i * shentsize
                    if off + 24 > len(data):
                        break
                    sh_off = struct.unpack_from(e + "I", data, off + 16)[0]
                    sh_size = struct.unpack_from(e + "I", data, off + 20)[0]
                    end = max(end, sh_off + sh_size)
                return end
        if data[:2] == b"MZ":
            e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
            coff = e_lfanew + 4
            nsect = struct.unpack_from("<H", data, coff + 2)[0]
            opt_size = struct.unpack_from("<H", data, coff + 16)[0]
            sect = coff + 20 + opt_size
            end = 0
            for i in range(nsect):
                off = sect + i * 40
                if off + 40 > len(data):
                    break
                raw_size = struct.unpack_from("<I", data, off + 16)[0]
                raw_ptr = struct.unpack_from("<I", data, off + 20)[0]
                end = max(end, raw_ptr + raw_size)
            return end
    except Exception:
        pass
    return 0


def find_sigs(data: bytes):
    found = []
    for sig, name, ext in SIGS:
        start = 0
        while True:
            pos = data.find(sig, start)
            if pos == -1:
                break
            found.append((pos, name, ext))
            start = pos + 1
    found.sort()
    return found


def pyc_info(path: str, data: bytes):
    info = {"strings": [], "disasm": "", "constants": []}
    for hdr in (16, 12, 8, 4):
        try:
            code = marshal.loads(data[hdr:])
            break
        except Exception:
            code = None
    if code is None:
        return info
    consts = []

    def walk(c):
        if hasattr(c, "co_consts"):
            for x in c.co_consts:
                if isinstance(x, str):
                    info["strings"].append(x)
                elif isinstance(x, (bytes, bytearray)):
                    info["strings"].append(x.decode("latin-1", "replace"))
                elif isinstance(x, int):
                    consts.append(x)
                walk(x)
        if hasattr(c, "co_names"):
            info["strings"] += [n for n in c.co_names if isinstance(n, str)]

    walk(code)
    info["constants"] = consts[:200]
    try:
        import dis
        buf = io.StringIO()
        dis.dis(code, file=buf)
        info["disasm"] = buf.getvalue()[:200000]
    except Exception:
        pass
    return info


def scan_raw_flags(data: bytes, keys, report):
    """Ищет флаги в расшифрованных байтах, даже если вокруг бинарный мусор."""
    from Crypto.Cipher import AES, ARC4
    chunks = [data] if len(data) <= 65536 else [data[-65536:]]
    for key, label in list(keys.items())[:120]:
        outs = []
        # XOR с разными фазами: флаг может начинаться не с начала ключа
        for chunk in chunks:
            for phase in range(min(len(key), 32)):
                outs.append((f"xor phase={phase}", bytes(
                    c ^ key[i % len(key)] for i, c in enumerate(chunk[phase:]))))
        try:
            outs.append(("rc4", ARC4.new(key).decrypt(data[:262144])))
        except Exception:
            pass
        for klen in (16, 24, 32):
            kb = hashlib.sha256(key).digest()[:klen]
            for mode, iv in (("ecb", None), ("cbc0", b"\x00" * 16)):
                try:
                    dec = (AES.new(kb, AES.MODE_ECB).decrypt(data[:262144]) if mode == "ecb"
                           else AES.new(kb, AES.MODE_CBC, iv).decrypt(data[:262144]))
                    outs.append((f"aes-{mode}", dec))
                except Exception:
                    pass
        for how, out in outs:
            for f in common.find_flags(out):
                if f not in report["flags"]:
                    report["flags"].append(f)
                    print(f"[!!!] {how} + {label}: {f}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("target", nargs="*", help="файлы (можно просто перечислить позицией)")
    ap.add_argument("--file", action="append", default=[])
    ap.add_argument("--dir", action="append", default=[])
    ap.add_argument("--out")
    ap.add_argument("--deep", action="store_true")
    ap.add_argument("--top", type=int, default=20)
    ap.add_argument("--time", type=int, default=90)
    ap.add_argument("--no-crypto", action="store_true")
    ap.add_argument("--min-score", type=float, default=3.0)
    ap.add_argument("--show-noise", action="store_true", help="показывать мусорные кандидаты")
    ap.add_argument("--json", action="store_true")
    common.add_flag_args(ap)
    args = ap.parse_args()
    common.apply_flag_args(args)

    paths = list(args.file) + list(args.target)
    for d in args.dir:
        for root, _, files in os.walk(d):
            for f in files[:100]:
                paths.append(os.path.join(root, f))
    if not paths:
        ap.error("нужен --file или --dir")

    report = {"files": [], "flags": [], "candidates": [], "notes": []}
    best = {}
    tokens = {}
    blobs = []
    deadline = time.time() + args.time

    for path in paths:
        try:
            data = open(path, "rb").read(20_000_000)
        except OSError:
            continue
        label = os.path.basename(path)
        print(f"\n=== {path} ({len(data)} b) ===")
        kind = "PYC" if path.lower().endswith(".pyc") else common.sniff(data)
        info = {"path": path, "size": len(data), "type": kind}
        print(f"[+] тип: {kind}")

        # защиты
        if data[:4] == b"\x7fELF":
            info["checksec"] = checksec.elf_info(data)
        elif data[:2] == b"MZ":
            info["checksec"] = checksec.pe_info(data)
        if "checksec" in info:
            print("[+]", info["checksec"])
            arch = (info["checksec"] or {}).get("arch", "")
            if arch and arch not in ("x86", "x86_64", "x64", "AMD64", "i386"):
                print(f"[i] {arch}: статика — здесь, динамика — "
                      f"`python linux/wsl.py run <bin> --arch auto` (qemu-aarch64) "
                      f"или инстанс задачи")

        # упаковщики
        packers = []
        for sig, name, advice in MARKERS:
            if sig in data:
                packers.append((name, advice))
        for name, advice in packers:
            print(f"[+] маркер: {name} -> {advice}")

        # энтропия
        high = []
        for off in range(0, min(len(data), 5_000_000), 4096):
            e = entropy(data[off:off + 4096])
            if e > 7.5:
                high.append((off, round(e, 2)))
        if high:
            print(f"[+] высокая энтропия в {len(high)} блоках, первый @0x{high[0][0]:x}")
            info["high_entropy"] = high[:10]

        # хвост/оверлей
        end = section_end(data)
        if 0 < end < len(data) - 16:
            tail = data[end:]
            print(f"[+] оверлей/хвост: {len(tail)} b @0x{end:x}")
            blobs.append((f"{label}:tail", tail[:1_000_000]))

        # вложенные файлы
        sigs = find_sigs(data)
        interesting = [s for s in sigs if s[0] > 0 or s[1] not in ("ELF", "ZIP")]
        for i, (off, name, ext) in enumerate(interesting[:5]):
            nxt = interesting[i + 1][0] if i + 1 < len(interesting) else len(data)
            blob = data[off:nxt][:1_000_000]
            print(f"[+] вложено: {name} @0x{off:x} ({len(blob)} b)")
            blobs.append((f"{label}:{name}@0x{off:x}", blob))
            if args.out:
                os.makedirs(args.out, exist_ok=True)
                open(os.path.join(args.out, f"{label}_{i}_{name}{ext}"), "wb").write(blob)

        # строки
        strs = common.strings(data, 6, 500) + utf16_strings(data, 4, 200)
        interesting_s = []
        for off, s in strs:
            if any(k in s.lower() for k in KEYWORDS) or common.FLAG_RE.search(s.encode("latin-1", "ignore")):
                interesting_s.append(s)
            mg.add_token(tokens, s, f"{label}:str")
            for how, dec in common.decode_field(s):
                if how != "raw" and dec:
                    mg.add_token(tokens, dec.decode("latin-1", "replace"), f"{label}:{how}")
        mg.add_token(tokens, os.path.splitext(label)[0], "filename")
        for s in interesting_s[:30]:
            print("  str:", s[:160])

        # короткий числовой/hex секрет рядом со словом PIN/key/code/pass
        secret_hits = []
        for off, s in common.strings(data, 3, 3000):
            if s in ("",) or not (3 <= len(s) <= 10):
                continue
            digits = sum(c.isdigit() for c in s)
            if digits < 3 or digits != sum(c.isalnum() for c in s):
                continue
            window = data[max(0, off - 256):off + 256].lower()
            if any(k.encode() in window for k in SECRET_WORDS):
                secret_hits.append((off, s))
        for off, s in secret_hits[:10]:
            print(f"[!] возможный PIN/код: {s!r} @0x{off:x} (рядом ключевое слово)")
            report["notes"].append(f"secret-like: {s} @0x{off:x}")

        # флаги в строках/сырых данных
        for f in common.find_flags(data):
            report["flags"].append(f)

        # pyc
        if path.lower().endswith(".pyc") or data[:4] in (b"\xcb\r\r\n", b"\x6f\r\r\n"):
            pi = pyc_info(path, data)
            print(f"[+] pyc: строк={len(pi['strings'])} констант={len(pi['constants'])}")
            for s in pi["strings"][:20]:
                print("  const:", s[:120])
            for s in pi["strings"]:
                mg.add_token(tokens, s, f"{label}:pyc")
            for c in pi["constants"]:
                mg.add_token(tokens, str(c), f"{label}:const")
            if pi["disasm"]:
                # ищем сравнения и константы в дизассемблере
                for line in pi["disasm"].splitlines():
                    if "LOAD_CONST" in line or "COMPARE_OP" in line:
                        mg.add_token(tokens, line.strip(), f"{label}:dis")

        # маленький бинарник целиком — кандидат
        if len(data) <= 200_000 and not common.is_text(data):
            blobs.append((f"{label}:whole", data))
        elif len(data) > 200_000:
            blobs.append((f"{label}:head", data[:200_000]))

        report["files"].append(info)

    # перебор
    if not args.no_crypto:
        keys = mg.key_candidates(tokens, 60, 12)
        print(f"\n[+] токенов: {len(tokens)}  ключей: {len(keys)}  блобов: {len(blobs)}")
        for label, blob in blobs[:10]:
            if time.time() > deadline:
                print("[!] лимит времени")
                break
            ac.add_candidate(best, f"[{label}] raw", blob)
            # текстовый перебор имеет смысл только для более-менее текстовых блобов;
            # для бинарников флаги ловит scan_raw_flags
            if common.printable_ratio(blob) >= 0.5:
                ac.transform_bytes(blob, f"[{label}] ", best, deep=args.deep)
            scan_raw_flags(blob, keys, report)
            for key, klabel in list(keys.items())[:250]:
                if time.time() > deadline:
                    break
                mg.try_key(blob, f"[{label}] {klabel}", key, best, deep=args.deep)

    ranked = sorted(best.values(), key=lambda x: -x[0])
    for sc, how, text in ranked:
        f = ac.find_flag(text)
        if f:
            report["flags"].append(f)

    if args.json:
        report["candidates"] = [{"score": sc, "how": how, "text": t[:500]}
                                for sc, how, t in ranked[:args.top]]
        print(json.dumps(report, ensure_ascii=False, indent=2, default=str))
        return

    flags = sorted(set(report["flags"]))
    if flags:
        print("\n=== ФЛАГИ ===")
        for f in flags:
            print(" !!!", f)
    print("\n=== КАНДИДАТЫ ===")
    shown = 0
    for sc, how, text in ranked:
        if sc < args.min_score:
            continue
        flag = ac.find_flag(text)
        if not flag and not args.show_noise and common.printable_ratio(text) < 0.65:
            continue
        mark = "!!!" if flag else "   "
        print(f"\n{mark} score={sc:7.1f}  {how}")
        print("    " + text[:260].replace("\n", "\\n"))
        shown += 1
        if shown >= args.top:
            break
    if not shown:
        print("[-] без результата. Дальше: Ghidra/IDA, xrefs к строкам, "
              "проверь упаковщик и оверлей.")


if __name__ == "__main__":
    main()
