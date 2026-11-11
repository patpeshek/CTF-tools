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
import struct

# предохранители: сигнатуры легко размножить, а solve зовёт carve сам
MAX_FILES = 1000                    # вырезанных файлов за запуск
MAX_TOTAL_MIN = 16 << 20            # всего на диск: max(16 МБ, 4 x размер входа)

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


def _gif_subblocks(data: bytes, i: int) -> int:
    n = len(data)
    while i < n:
        size = data[i]
        i += 1
        if size == 0:
            return i
        i += size
    return -1


def gif_end(data: bytes, pos: int) -> int:
    """Конец GIF по структуре: блоки 0x21/0x2C и их sub-blocks, затем 0x3B.

    Наивный поиск первого 0x3B ломается: этот байт свободно встречается в
    LZW-данных и в extension-блоках.
    """
    n = len(data)
    if data[pos:pos + 3] != b"GIF":
        return -1
    i = pos + 6
    if i + 7 > n:
        return -1
    packed = data[i + 4]
    i += 7
    if packed & 0x80:                       # global color table
        i += 3 * (1 << ((packed & 0x07) + 1))
    while i < n:
        block = data[i]
        if block == 0x3B:                   # trailer
            return i + 1
        if block == 0x21:                   # extension
            i += 2                          # introducer + label
            i = _gif_subblocks(data, i)
            if i == -1:
                return -1
        elif block == 0x2C:                 # image descriptor
            i += 1
            if i + 9 > n:
                return -1
            local = data[i + 8]
            i += 9
            if local & 0x80:                # local color table
                i += 3 * (1 << ((local & 0x07) + 1))
            i += 1                          # LZW minimum code size
            i = _gif_subblocks(data, i)
            if i == -1:
                return -1
        else:
            return -1
    return -1


def _jpeg_entropy_end(data: bytes, i: int) -> int:
    """Энтропийные данные после заголовка SOS идут до первого настоящего
    маркера: FF00 — байт-стаффинг, FFD0..FFD7 — RSTn, FFFF — заполнитель.
    Возвращает смещение FF этого маркера (EOI, DHT/SOS прогрессивного JPEG…)."""
    n = len(data)
    while True:
        j = data.find(b"\xff", i)
        if j == -1 or j + 1 >= n:
            return -1
        nxt = data[j + 1]
        if nxt == 0x00 or 0xD0 <= nxt <= 0xD7:
            i = j + 2
        elif nxt == 0xFF:
            i = j + 1
        else:
            return j


def jpeg_end(data: bytes, pos: int) -> int:
    """Конец JPEG по маркерам: сегменты по длинам (EXIF-миниатюра в APP1
    со своим FFD9 пропускается), после SOS — энтропийные данные до
    настоящего маркера; сканов может быть несколько (progressive)."""
    n = len(data)
    if data[pos:pos + 2] != b"\xff\xd8":
        return -1
    i = pos + 2
    while i + 1 < n:
        if data[i] != 0xFF:                 # мусор — ищем следующий маркер
            nxt = data.find(b"\xff", i)
            if nxt == -1:
                return -1
            i = nxt
        while i < n and data[i] == 0xFF:    # fill bytes
            i += 1
        if i >= n:
            return -1
        marker = data[i]
        i += 1
        if marker == 0xD9:                  # EOI
            return i
        if marker == 0x01 or 0xD0 <= marker <= 0xD8:
            continue                        # TEM / RSTn / SOI: без длины
        if i + 2 > n:
            return -1
        seg_len = int.from_bytes(data[i:i + 2], "big")
        if seg_len < 2:
            return -1
        if marker == 0xDA:                  # SOS: дальше энтропийные данные
            i = _jpeg_entropy_end(data, i + seg_len)
            if i == -1:
                return -1
            continue                        # стоим на FF следующего маркера
        i += seg_len
    return -1


def pcap_end(data: bytes, pos: int) -> int:
    """Конец PCAP по записям: 24 байта заголовка, затем записи 16 + incl_len.

    -1 — заголовок не похож на pcap (4 байта magic сами по себе ничего не
    значат). Записи читаются, пока длина правдоподобна и влезает в файл.
    """
    n = len(data)
    if pos + 24 > n:
        return -1
    magic = data[pos:pos + 4]
    if magic == b"\xd4\xc3\xb2\xa1":
        e = "<"
    elif magic == b"\xa1\xb2\xc3\xd4":
        e = ">"
    else:
        return -1
    major, minor, _zone, _sigfigs, snaplen, _link = struct.unpack(
        e + "HHiIII", data[pos + 4:pos + 24])
    if major != 2 or minor > 4:
        return -1
    limit = max(snaplen, 262144)
    i = pos + 24
    while i + 16 <= n:
        incl = struct.unpack(e + "I", data[i + 8:i + 12])[0]
        if incl > limit or i + 16 + incl > n:
            break
        i += 16 + incl
    return i


def pcapng_end(data: bytes, pos: int) -> int:
    """Конец PCAPNG по блокам: тип, длина, тело, та же длина в конце.

    Первый блок обязан быть Section Header с magic порядка байт, иначе -1.
    """
    n = len(data)
    i = pos
    e = None
    while i + 12 <= n:
        if data[i:i + 4] == b"\x0a\x0d\x0d\x0a":         # Section Header Block
            bom = data[i + 8:i + 12]
            if bom == b"\x4d\x3c\x2b\x1a":
                e = "<"
            elif bom == b"\x1a\x2b\x3c\x4d":
                e = ">"
            else:
                break
        elif e is None:
            break
        blen = struct.unpack(e + "I", data[i + 4:i + 8])[0]
        if blen < 12 or blen % 4 or i + blen > n:
            break
        if data[i + blen - 4:i + blen] != data[i + 4:i + 8]:
            break
        i += blen
    return i if i > pos else -1


def _tar_checksum_ok(data: bytes, start: int) -> bool:
    if start < 0 or start + 512 > len(data):
        return False
    header = data[start:start + 512]
    if not header[:100].strip(b"\x00"):
        return False
    raw = header[148:156].strip(b"\x00 ")
    if not raw:
        return False
    try:
        want = int(raw, 8)
    except ValueError:
        return False
    got = sum(header[:148]) + 8 * 0x20 + sum(header[156:])
    return got == want


def tar_end(data: bytes, start: int) -> int:
    """Конец TAR: заголовки по 512 байт, данные с выравниванием, два нулевых
    блока в конце. Позволяет не приклеивать мусор после архива."""
    n = len(data)
    i = start
    zeros = 0
    while i + 512 <= n:
        header = data[i:i + 512]
        if header == b"\x00" * 512:
            zeros += 1
            i += 512
            if zeros >= 2:
                return i
            continue
        zeros = 0
        if not _tar_checksum_ok(data, i):
            return i if i > start else -1
        size_raw = header[124:136].strip(b"\x00 ").strip()
        try:
            size = int(size_raw, 8) if size_raw else 0
        except ValueError:
            return -1
        i += 512 + ((size + 511) // 512) * 512
    return min(i, n)


def extent(data: bytes, found, i: int) -> int:
    pos, ext = found[i][0], found[i][1]
    if ext == ".zip":
        end = zip_end(data, pos)
        if end != -1:
            return end
        print(f"[!] ZIP на {pos}: не нашёл EOCD, режу по следующей сигнатуре")
    if ext in (".pcapng", ".pcap"):
        # pcap — внешний контейнер: внутри него свои сигнатуры (картинки,
        # exe в HTTP-трафике), резать по ним нельзя. Конец — по записям,
        # а не «до конца файла»: иначе каждая сигнатура тянет весь хвост.
        end = (pcap_end if ext == ".pcap" else pcapng_end)(data, pos)
        if end != -1:
            return end
    if ext == ".png":
        iend = data.find(b"IEND", pos)
        if iend != -1 and iend + 8 <= len(data):
            return iend + 8
    if ext == ".jpg":
        end = jpeg_end(data, pos)
        if end != -1:
            return end
        eoi = data.find(b"\xff\xd9", pos)
        if eoi != -1:
            return eoi + 2
    if ext == ".gif":
        end = gif_end(data, pos)
        if end != -1:
            return end
        term = data.find(b"\x3b", pos + 6)
        if term != -1:
            return term + 1
    if ext == ".tar":
        end = tar_end(data, pos)
        if end != -1:
            return end
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
            sigpos = data.find(sig, start)
            if sigpos == -1:
                break
            pos = sigpos
            if ext == ".tar":
                # сигнатура ustar лежит на 257-м байте заголовка
                begin = sigpos - 257
                if begin < 0 or not _tar_checksum_ok(data, begin):
                    start = sigpos + 1
                    continue
                pos = begin
            elif ext in (".pcap", ".pcapng") and sigpos > 0 and \
                    (pcap_end if ext == ".pcap" else pcapng_end)(data, sigpos) == -1:
                # голые 4 байта magic / "\n\r\r\n" без заголовка — не вложение
                start = sigpos + 1
                continue
            found.append((pos, ext, name, sig))
            start = sigpos + 1

    found.sort()
    # сигнатура самого файла на нулевом смещении — это он сам, не вложение
    found = [f for f in found if f[0] > 0]
    if not found:
        print("[-] сигнатур не найдено")
        return

    ends = [extent(data, found, i) for i in range(len(found))]
    print(f"[+] найдено вложений: {len(found)}")
    for i, (pos, ext, name, sig) in enumerate(found):
        print(f"  {i:2d}. {name:16s} offset={pos:<10d} len={ends[i] - pos:<10d} -> *{ext}")

    if args.out:
        os.makedirs(args.out, exist_ok=True)
        budget = max(MAX_TOTAL_MIN, 4 * len(data))
        written = files = skipped = 0
        for i, (pos, ext, name, sig) in enumerate(found):
            end = ends[i]
            if files >= MAX_FILES or written + (end - pos) > budget:
                skipped += 1
                continue
            path = os.path.join(args.out, f"{i:02d}_{name.replace(' ', '_').replace('/', '_')}{ext}")
            open(path, "wb").write(data[pos:end])
            written += end - pos
            files += 1
            print(f"[+] {path}")
        if skipped:
            print(f"[!] лимит (до {MAX_FILES} файлов, до {budget} байт): "
                  f"не записано вложений: {skipped} (см. список выше)")

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
