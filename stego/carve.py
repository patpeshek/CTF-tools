#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
carve.py — поиск и вырезание вложенных файлов по сигнатурам (замена binwalk/foremost).

  python carve.py suspicious.bin --list
  python carve.py suspicious.bin --out carved
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

SIGS = [
    (b"\x89PNG\r\n\x1a\n", ".png", "PNG"),
    (b"\xff\xd8\xff", ".jpg", "JPEG"),
    (b"GIF87a", ".gif", "GIF87a"),
    (b"GIF89a", ".gif", "GIF89a"),
    (b"PK\x03\x04", ".zip", "ZIP"),
    (b"\x1f\x8b\x08", ".gz", "GZIP"),
    (b"BZh9", ".bz2", "BZIP2"),
    (b"\xfd7zXZ\x00", ".xz", "XZ"),
    (b"7z\xbc\xaf\x27\x1c", ".7z", "7Z"),
    (b"Rar!\x1a\x07", ".rar", "RAR"),
    (b"%PDF", ".pdf", "PDF"),
    (b"\x7fELF", ".elf", "ELF"),
    (b"SQLite format 3\x00", ".sqlite", "SQLite"),
    (b"LUKS\xba\xbe", ".luks", "LUKS"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", ".doc", "OLE (doc/xls)"),
    (b"ustar\x0000", ".tar", "TAR"),
    (b"MZ", ".exe", "PE/EXE"),
    (b"\x0a\x0d\x0d\x0a", ".pcapng", "PCAPNG"),
    (b"\xd4\xc3\xb2\xa1", ".pcap", "PCAP"),
    (b"\xa1\xb2\xc3\xd4", ".pcap", "PCAP-be"),
    (b"ID3", ".mp3", "MP3"),
    (b"OggS", ".ogg", "OGG"),
    (b"fLaC", ".flac", "FLAC"),
    (b"\x00asm", ".wasm", "WASM"),
]


def zip_end(data: bytes, pos: int) -> int:
    """Конец ZIP по EOCD (PK\\x05\\x06), а не по следующей сигнатуре.

    Иначе к архиву прилипает мусор после него и zipfile его не открывает.
    """
    eocd = data.find(b"PK\x05\x06", pos)
    if eocd == -1:
        return -1
    if eocd + 22 > len(data):
        return -1
    comment_len = int.from_bytes(data[eocd + 20:eocd + 22], "little")
    end = eocd + 22 + comment_len
    return end if end <= len(data) else len(data)


def extent(data: bytes, found, i: int) -> int:
    pos, ext = found[i][0], found[i][1]
    if ext == ".zip":
        end = zip_end(data, pos)
        if end != -1:
            return end
        print(f"[!] ZIP на {pos}: не нашёл EOCD, режу по следующей сигнатуре")
    if ext in (".pcapng", ".pcap"):
        # pcap — внешний контейнер: внутри него свои сигнатуры (картинки,
        # exe в HTTP-трафике), резать по ним нельзя.
        return len(data)
    if ext == ".png":
        iend = data.find(b"IEND", pos)
        if iend != -1 and iend + 8 <= len(data):
            return iend + 8
    if ext == ".jpg":
        eoi = data.find(b"\xff\xd9", pos)
        if eoi != -1:
            return eoi + 2
    if ext == ".gif":
        term = data.find(b"\x3b", pos + 6)
        if term != -1:
            return term + 1
    return found[i + 1][0] if i + 1 < len(found) else len(data)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("file")
    ap.add_argument("--out", help="папка для вырезанных файлов")
    ap.add_argument("--list", action="store_true")
    args = ap.parse_args()

    data = open(args.file, "rb").read()
    found = []
    for sig, ext, name in SIGS:
        start = 0
        while True:
            pos = data.find(sig, start)
            if pos == -1:
                break
            found.append((pos, ext, name, sig))
            start = pos + 1

    found.sort()
    # сигнатура самого файла на нулевом смещении — это он сам, не вложение
    found = [f for f in found if f[0] > 0]
    if not found:
        print("[-] сигнатур не найдено")
        return

    print(f"[+] найдено вложений: {len(found)}")
    for i, (pos, ext, name, sig) in enumerate(found):
        end = extent(data, found, i)
        print(f"  {i:2d}. {name:16s} offset={pos:<10d} len={end - pos:<10d} -> *{ext}")

    if args.out:
        os.makedirs(args.out, exist_ok=True)
        for i, (pos, ext, name, sig) in enumerate(found):
            end = extent(data, found, i)
            path = os.path.join(args.out, f"{i:02d}_{name.replace(' ', '_').replace('/', '_')}{ext}")
            open(path, "wb").write(data[pos:end])
            print(f"[+] {path}")

        # если это ZIP — покажем содержимое и попробуем открыть
        import zipfile
        for f in sorted(os.listdir(args.out)):
            if not f.endswith(".zip"):
                continue
            path = os.path.join(args.out, f)
            for pwd in (None, b"", b"password", b"infected", b"secret", b"1234",
                        b"12345", b"123456", b"flag", b"ctf"):
                try:
                    with zipfile.ZipFile(path) as z:
                        names = z.namelist()[:20]
                        print(f"[+] {f}: {len(names)} записей" +
                              ("" if pwd in (None, b"") else f", пароль {pwd!r}"))
                        print("    ", names)
                        if pwd not in (None, b""):
                            z.extractall(args.out, pwd=pwd)
                            print("    [+] распаковано")
                        else:
                            z.extractall(args.out)
                            print("    [+] распаковано")
                    break
                except RuntimeError as e:
                    if "password" in str(e).lower():
                        continue
                    print(f"[!] {f}: {e}")
                    break
                except Exception as e:
                    print(f"[!] {f}: {e}")
                    break


if __name__ == "__main__":
    try:
        main()
    except (FileNotFoundError, IsADirectoryError, PermissionError) as e:
        print(f"[-] не могу открыть: {getattr(e, 'filename', None) or e}")
    except BrokenPipeError:
        pass
    except KeyboardInterrupt:
        print("\n[-] прервано")
