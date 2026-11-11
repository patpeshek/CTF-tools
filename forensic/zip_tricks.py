#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
zip_tricks.py — приёмы с ZIP из CTF.

  python zip_tricks.py info ZIP
  python zip_tricks.py fakecrypt ZIP [--out DIR]
  python zip_tricks.py crc-brute ZIP [--min 1 --max 6 --charset printable]
  python zip_tricks.py password ZIP [--wordlist FILE] [--password P ...]
  python zip_tricks.py known-plaintext ZIP [--plain FILE | --magic png|xml|zip]

bkcrack необязателен: если его нет в PATH, печатается готовая команда.
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
import itertools
import os
import shutil
import string
import struct
import subprocess
import sys
import zipfile
import zlib

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import common  # noqa: E402

CD_FMT = "<4s6H3I5H2I"      # central directory file header
LH_FMT = "<4s5H3I2H"        # local file header
CD_SIZE = struct.calcsize(CD_FMT)
LH_SIZE = struct.calcsize(LH_FMT)

CHARSETS = {
    "printable": bytes(range(32, 127)),
    "alnum": (string.ascii_letters + string.digits).encode(),
    "lower": string.ascii_lowercase.encode(),
    "upper": string.ascii_uppercase.encode(),
    "digits": string.digits.encode(),
    "hex": b"0123456789abcdef",
    "flag": (string.ascii_letters + string.digits + "_{}-!").encode(),
    "all": bytes(range(256)),
}

MAGICS = {
    "png": bytes.fromhex("89504e470d0a1a0a0000000d49484452"),
    "zip": bytes.fromhex("504b0304"),
    "xml": b'<?xml version="1.0" encoding="UTF-8"',
}

DEFAULT_WORDS = [
    "password", "123456", "12345678", "qwerty", "admin", "letmein", "secret",
    "infected", "flag", "ctf", "pass", "root", "toor", "test", "zip", "1234",
    "123456789", "iloveyou", "welcome", "changeme", "default", "guest",
    "password1", "p@ssw0rd", "P@ssw0rd", "hunter2", "monkey", "dragon",
    "football", "abc123", "111111", "000000", "0000", "1111", "5555", "9999",
    "challenge", "ctf2024", "ctf2025", "flag{", "hacker", "login", "master",
]


class Entry:
    def __init__(self):
        self.name = ""
        self.cd_pos = 0
        self.lh_pos = 0
        self.cd_flags = 0
        self.lh_flags = None
        self.method = 0
        self.crc = 0
        self.csize = 0
        self.usize = 0
        self.data_pos = 0

    @property
    def enc_cd(self):
        return bool(self.cd_flags & 1)

    @property
    def enc_lh(self):
        return None if self.lh_flags is None else bool(self.lh_flags & 1)

    @property
    def is_dir(self):
        return self.name.endswith("/")


def parse_zip(data: bytes):
    """Читаем central directory и local headers напрямую."""
    eocd = data.rfind(b"PK\x05\x06")
    if eocd < 0 or eocd + 22 > len(data):
        raise ValueError("нет EOCD (не ZIP или обрезан)")
    (_s, _d, _d2, _n, total, cd_size, cd_off, _cl) = struct.unpack(
        "<4s4H2IH", data[eocd:eocd + 22])
    delta = eocd - cd_size - cd_off if eocd - cd_size - cd_off > 0 else 0
    pos = cd_off + delta
    out = []
    for _ in range(total):
        if pos + CD_SIZE > len(data) or data[pos:pos + 4] != b"PK\x01\x02":
            break
        (_s, _vm, _vn, flags, method, _t, _dt, crc, csize, usize,
         nlen, elen, clen, _dn, _ia, _ea, lhoff) = struct.unpack(
            CD_FMT, data[pos:pos + CD_SIZE])
        e = Entry()
        e.cd_pos, e.cd_flags, e.method = pos, flags, method
        e.crc, e.csize, e.usize = crc, csize, usize
        e.name = data[pos + CD_SIZE:pos + CD_SIZE + nlen].decode("utf-8", "replace")
        e.lh_pos = lhoff + delta
        if data[e.lh_pos:e.lh_pos + 4] == b"PK\x03\x04":
            lh = struct.unpack(LH_FMT, data[e.lh_pos:e.lh_pos + LH_SIZE])
            e.lh_flags = lh[2]
            e.data_pos = e.lh_pos + LH_SIZE + lh[9] + lh[10]
        out.append(e)
        pos += CD_SIZE + nlen + elen + clen
    return out


def read_file(path):
    with open(path, "rb") as f:
        return f.read()


def raw_data(data, e):
    return data[e.data_pos:e.data_pos + e.csize]


def looks_plain(data, e):
    """Данные записи лежат открытыми и совпадают с CRC из заголовка."""
    raw = raw_data(data, e)
    try:
        if e.method == 0:
            body = raw
        elif e.method == 8:
            d = zlib.decompressobj(-15)
            body = d.decompress(raw)
        else:
            return None
    except Exception:
        return None
    return (zlib.crc32(body) & 0xFFFFFFFF) == e.crc and len(body) == e.usize


def emit_flags(blob: bytes, where: str):
    for fl in common.find_flags(blob):
        print(f"[FLAG] {fl}   ({where})")


# ---------------------------------------------------------------- info

def cmd_info(args):
    data = read_file(args.zip)
    es = parse_zip(data)
    print(f"[+] записей: {len(es)}")
    print(f"    {'имя':32s} {'meth':>4} {'csize':>8} {'usize':>8} {'crc32':>8}  encCD encLH")
    for e in es:
        lh = "?" if e.enc_lh is None else int(e.enc_lh)
        note = ""
        if e.method == 99:
            note = "  AES"
        elif e.enc_lh is not None and e.enc_cd != e.enc_lh:
            note = "  <-- флаги CD и LH расходятся"
        print(f"    {e.name[:32]:32s} {e.method:>4} {e.csize:>8} {e.usize:>8} "
              f"{e.crc:08x}  {int(e.enc_cd):>5} {lh:>5}{note}")
    enc = [e for e in es if e.enc_cd or e.enc_lh]
    if enc:
        print("[i] есть записи с битом шифрования; проверь: zip_tricks fakecrypt "
              "(бит стоит, а данные открыты) / password / known-plaintext")
    tiny = [e for e in es if not e.is_dir and 0 < e.usize <= 6]
    if len(tiny) >= 3:
        print(f"[i] {len(tiny)} крошечных записей (<=6 байт): флаг мог быть разрезан; "
              "zip_tricks crc-brute")
    return 0


# ---------------------------------------------------------------- fakecrypt

def cmd_fakecrypt(args):
    data = read_file(args.zip)
    es = parse_zip(data)
    marked = [e for e in es if (e.enc_cd or e.enc_lh) and not e.is_dir]
    if not marked:
        print("[-] ни у одной записи нет бита шифрования — fakecrypt не нужен")
        return 0
    fake = []
    for e in marked:
        verdict = looks_plain(data, e)
        if verdict:
            fake.append(e)
            print(f"[+] {e.name}: бит шифрования стоит, но данные открыты (CRC сошёлся)")
        elif verdict is None:
            print(f"[-] {e.name}: метод {e.method}, проверить не могу "
                  "(AES/неизвестный метод — по-настоящему зашифрован)")
        else:
            print(f"[-] {e.name}: по-настоящему зашифрован (CRC не сошёлся)")
    if not fake:
        print("[-] фейкового шифрования нет; дальше: password / known-plaintext")
        return 0
    buf = bytearray(data)
    for e in fake:
        struct.pack_into("<H", buf, e.cd_pos + 8, e.cd_flags & ~1 & ~0x40)
        if e.lh_flags is not None:
            struct.pack_into("<H", buf, e.lh_pos + 6, e.lh_flags & ~1 & ~0x40)
    out = args.out or os.path.splitext(args.zip)[0] + "_fixed"
    os.makedirs(out, exist_ok=True)
    fixed = os.path.join(out, "fixed.zip")
    with open(fixed, "wb") as f:
        f.write(buf)
    print(f"[+] исправленная копия: {fixed}")
    ok = 0
    names = {e.name for e in fake}
    with zipfile.ZipFile(io.BytesIO(bytes(buf))) as z:
        for info in z.infolist():
            if info.filename not in names:
                continue
            try:
                body = z.read(info)          # zipfile сам сверяет CRC
            except Exception as ex:
                print(f"[-] {info.filename}: {ex}")
                continue
            ok += 1
            dest = os.path.join(out, *[p for p in info.filename.split("/") if p not in ("", ".", "..")])
            os.makedirs(os.path.dirname(dest) or out, exist_ok=True)
            with open(dest, "wb") as f:
                f.write(body)
            print(f"[+] извлечён {info.filename} ({len(body)} b, CRC ок) -> {dest}")
            emit_flags(body, info.filename)
    print(f"[+] извлечено с проверкой CRC: {ok}/{len(fake)}")
    return 0


import io  # noqa: E402  (после определения, чтобы шапка осталась короткой)


# ---------------------------------------------------------------- crc-brute

def _table():
    t = []
    for n in range(256):
        c = n
        for _ in range(8):
            c = (c >> 1) ^ 0xEDB88320 if c & 1 else c >> 1
        t.append(c)
    return t


def crc_search(target: int, length: int, charset: bytes, limit_hits=4):
    """Все строки длины length из charset с данным CRC32 (до limit_hits)."""
    hits = []
    try:
        import numpy as np
    except Exception:
        np = None
    if np is None or length <= 2:
        for combo in itertools.product(charset, repeat=length):
            b = bytes(combo)
            if zlib.crc32(b) & 0xFFFFFFFF == target:
                hits.append(b)
                if len(hits) >= limit_hits:
                    break
        return hits
    tab = np.array(_table(), dtype=np.uint32)
    cs = np.frombuffer(charset, dtype=np.uint8).astype(np.uint32)
    tail = min(length, 3)
    head = length - tail
    # хвост из tail байт: состояния CRC для всех комбинаций (без финального xor)
    for prefix in itertools.product(charset, repeat=head):
        st = np.array([(zlib.crc32(bytes(prefix)) ^ 0xFFFFFFFF) & 0xFFFFFFFF
                       if head else 0xFFFFFFFF], dtype=np.uint32)
        for _ in range(tail):
            idx = ((st[:, None] ^ cs[None, :]) & 0xFF)
            st = (tab[idx] ^ (st[:, None] >> 8)).reshape(-1)
        found = np.nonzero((st ^ np.uint32(0xFFFFFFFF)) == np.uint32(target))[0]
        for pos in found:
            digits = []
            p = int(pos)
            for _ in range(tail):
                digits.append(charset[p % len(charset)])
                p //= len(charset)
            b = bytes(prefix) + bytes(reversed(digits))
            if zlib.crc32(b) & 0xFFFFFFFF == target:
                hits.append(b)
        if len(hits) >= limit_hits:
            break
    return hits[:limit_hits]


def cmd_crc_brute(args):
    data = read_file(args.zip)
    es = [e for e in parse_zip(data) if not e.is_dir]
    cs = CHARSETS.get(args.charset)
    if cs is None:
        print(f"[-] неизвестный charset {args.charset}; есть: {', '.join(CHARSETS)}")
        return 1
    parts, done, amb = [], 0, False
    for e in es:
        n = e.usize
        if n == 0:
            parts.append(b"")
            continue
        if not (args.min <= n <= args.max):
            parts.append(b"?" * min(n, 8))
            print(f"[-] {e.name}: размер {n} вне [{args.min},{args.max}] — пропуск")
            continue
        space = len(cs) ** n
        if space > args.limit:
            parts.append(b"?" * n)
            print(f"[!] {e.name}: пространство {space:.2e} > лимита {args.limit:.0e} "
                  f"(charset={args.charset}, len={n}); сузь --charset или подними --limit")
            continue
        hits = crc_search(e.crc, n, cs)
        if not hits:
            parts.append(b"?" * n)
            print(f"[-] {e.name}: в charset={args.charset} не найдено (crc {e.crc:08x})")
            continue
        done += 1
        if len(hits) > 1:
            amb = True
            print(f"[~] {e.name}: {len(hits)} коллизий CRC: "
                  + ", ".join(repr(h) for h in hits) + " (беру первую)")
        else:
            print(f"[+] {e.name}: {hits[0]!r}")
        parts.append(hits[0])
    joined = b"".join(parts)
    print(f"[+] восстановлено записей: {done}/{len([e for e in es if e.usize])}")
    print("[+] склейка в порядке архива:")
    print("    " + joined.decode("utf-8", "replace"))
    if amb:
        print("[i] были коллизии CRC (длина >=5): проверь варианты вручную")
    emit_flags(joined, "crc-brute")
    return 0


# ---------------------------------------------------------------- password

def load_words(args):
    words = list(args.password or [])
    if args.wordlist:
        try:
            with open(args.wordlist, "r", encoding="utf-8", errors="replace") as f:
                words += [ln.rstrip("\r\n") for ln in f if ln.strip()]
        except OSError as e:
            print(f"[-] словарь не открыть: {e}")
    words += DEFAULT_WORDS
    seen, out = set(), []
    for w in words:
        if w not in seen:
            seen.add(w)
            out.append(w)
    return out


def cmd_password(args):
    data = read_file(args.zip)
    es = [e for e in parse_zip(data) if not e.is_dir]
    enc = [e for e in es if e.enc_cd or e.enc_lh]
    if not enc:
        print("[-] шифрованных записей нет")
        return 0
    zc = [e for e in enc if e.method != 99]
    aes = [e for e in enc if e.method == 99]
    if aes:
        print(f"[!] AES-записей: {len(aes)} ({aes[0].name}...) — stdlib их не открывает; "
              "используй john (zip2john) / hashcat -m 13600 / 7z")
    if not zc:
        return 0
    target = min(zc, key=lambda e: e.csize)   # самая маленькая — быстрее проверка
    words = load_words(args)
    print(f"[i] пробую {len(words)} паролей на {target.name!r}")
    with zipfile.ZipFile(args.zip) as z:
        info = z.getinfo(target.name)
        found = None
        for w in words:
            try:
                z.read(info, pwd=w.encode("utf-8"))
                found = w
                break
            except Exception:
                continue
        if found is None:
            print("[-] пароль не найден (ZipCrypto). Дальше: больший словарь "
                  "(john/hashcat) или known-plaintext (bkcrack)")
            return 0
        print(f"[+] пароль: {found}")
        out = args.out
        if out:
            os.makedirs(out, exist_ok=True)
        for e in zc:
            try:
                body = z.read(z.getinfo(e.name), pwd=found.encode("utf-8"))
            except Exception as ex:
                print(f"[-] {e.name}: {ex}")
                continue
            print(f"[+] {e.name}: {len(body)} b")
            emit_flags(body, e.name)
            if out:
                dest = os.path.join(out, *[p for p in e.name.split("/") if p not in ("", ".", "..")])
                os.makedirs(os.path.dirname(dest) or out, exist_ok=True)
                with open(dest, "wb") as f:
                    f.write(body)
    return 0


# ---------------------------------------------------------------- known-plaintext

def cmd_known_plaintext(args):
    data = read_file(args.zip)
    es = [e for e in parse_zip(data) if not e.is_dir]
    zc = [e for e in es if (e.enc_cd or e.enc_lh) and e.method != 99]
    if not zc:
        print("[-] нет записей ZipCrypto (AES bkcrack не берёт)")
        return 0
    if args.entry:
        pick = [e for e in zc if e.name == args.entry]
        if not pick:
            print(f"[-] записи {args.entry!r} нет среди шифрованных")
            return 1
        target = pick[0]
    else:
        target = zc[0]
    q = lambda s: f'"{s}"' if " " in s else s
    zpath = q(os.path.abspath(args.zip))
    if args.plain:
        if not os.path.isfile(args.plain):
            print(f"[-] файл known-plaintext не найден: {args.plain}")
            return 1
        known = read_file(args.plain)
        base = f"bkcrack -C {zpath} -c {q(target.name)} -p {q(os.path.abspath(args.plain))}"
        why = f"known-plaintext из файла ({len(known)} b)"
    else:
        magic = MAGICS[args.magic or "png"]
        base = (f"bkcrack -C {zpath} -c {q(target.name)} -x 0 {magic.hex()}")
        why = f"известный заголовок {args.magic or 'png'} ({len(magic)} b)"
        known = magic
    if len(known) < 12:
        print(f"[!] bkcrack нужно >=12 известных байт (8 подряд); сейчас {len(known)}")
    if target.method == 8 and not args.plain:
        print("[i] запись сжата (deflate): заголовок известен только если plain — "
              "сжатый поток. Надёжнее --plain с тем же файлом, сжатым тем же способом "
              "(bkcrack -P plain.zip -p имя_в_plain.zip)")
    print(f"[i] цель: {target.name!r}, метод {target.method}; {why}")
    exe = shutil.which("bkcrack")
    if not exe:
        print("[!] bkcrack не найден в PATH. Запусти сам:")
        print("    " + base)
        print("    # получив ключи K0 K1 K2:")
        print(f"    bkcrack -C {zpath} -c {q(target.name)} -k K0 K1 K2 -d out.bin")
        print(f"    bkcrack -C {zpath} -k K0 K1 K2 -U new.zip новый_пароль")
        return 0
    cmd = [exe, "-C", os.path.abspath(args.zip), "-c", target.name]
    cmd += (["-p", os.path.abspath(args.plain)] if args.plain
            else ["-x", "0", known.hex()])
    print("[+] запускаю: " + " ".join(cmd))
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, errors="replace",
                           timeout=args.timeout)
    except subprocess.TimeoutExpired:
        print("[-] bkcrack: таймаут")
        return 0
    print(r.stdout[-2000:] + r.stderr[-500:])
    return 0


# ---------------------------------------------------------------- main

def main():
    ap = argparse.ArgumentParser(description="приёмы с ZIP")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("info")
    p.add_argument("zip")
    p = sub.add_parser("fakecrypt")
    p.add_argument("zip")
    p.add_argument("--out")
    p = sub.add_parser("crc-brute")
    p.add_argument("zip")
    p.add_argument("--min", type=int, default=1)
    p.add_argument("--max", type=int, default=6)
    p.add_argument("--charset", default="printable", help=",".join(CHARSETS))
    p.add_argument("--limit", type=float, default=1e8,
                   help="макс. число кандидатов на запись (по умолчанию 1e8)")
    p = sub.add_parser("password")
    p.add_argument("zip")
    p.add_argument("--wordlist")
    p.add_argument("--password", action="append", help="пароль из условия (можно несколько)")
    p.add_argument("--out")
    p = sub.add_parser("known-plaintext")
    p.add_argument("zip")
    p.add_argument("--plain")
    p.add_argument("--magic", choices=sorted(MAGICS))
    p.add_argument("--entry")
    p.add_argument("--timeout", type=int, default=300)
    args = ap.parse_args()
    fn = {"info": cmd_info, "fakecrypt": cmd_fakecrypt, "crc-brute": cmd_crc_brute,
          "password": cmd_password, "known-plaintext": cmd_known_plaintext}[args.cmd]
    return fn(args) or 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (FileNotFoundError, IsADirectoryError, PermissionError) as e:
        print(f"[-] не могу открыть: {getattr(e, 'filename', None) or e}")
    except ValueError as e:
        print(f"[-] {e}")
    except BrokenPipeError:
        pass
    except KeyboardInterrupt:
        print("\n[-] прервано")
