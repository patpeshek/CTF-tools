#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
bmp_stego.py — BMP: ручной разбор заголовка, данные за bfSize, битовые плоскости.

BMP часто «врёт» заголовком: biHeight и bfSize описывают картинку меньше той,
что реально лежит в файле (лишние строки пикселей дописаны в конец, а иногда в
начало — но там, где их не видно при обычном просмотре). Поэтому сначала
сравниваем заявленные размеры с реальным, а уже потом ищем стего.

Примеры:
  python bmp_stego.py pic.png               # заголовок + аномалии размеров
  python bmp_stego.py pic.png --tail        # хвост: энтропия, сигнатуры, распаковка, ASCII-арт
  python bmp_stego.py pic.png --planes      # bit-plane slicing по каналам
  python bmp_stego.py pic.png --tail --planes --json
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
import bz2
import collections
import lzma
import math
import os
import struct
import sys
import zlib

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import common  # noqa: E402

# сжатые контейнеры, которые стоит попробовать на хвосте
DECODERS = {
    "zlib": lambda b: zlib.decompressobj().decompress(b),
    "zlib-raw": lambda b: zlib.decompressobj(-15).decompress(b),
    "gzip": lambda b: zlib.decompressobj(31).decompress(b),
    "bz2": bz2.decompress,
    "lzma": lzma.decompress,
}
# сигнатуры вложенных файлов — ищем в хвосте
MAGICS = {
    b"BM": "BMP", b"\x89PNG\r\n\x1a\n": "PNG", b"PK\x03\x04": "ZIP",
    b"PK\x05\x06": "ZIP(empty)", b"7z\xbc\xaf\x27\x1c": "7z", b"\xff\xd8\xff": "JPEG",
    b"GIF89a": "GIF", b"GIF87a": "GIF", b"\x1f\x8b\x08": "GZIP", b"BZh": "BZ2",
    b"\xfd7zXZ\x00": "XZ", b"Rar!\x1a\x07": "RAR", b"%PDF-": "PDF",
    b"\x7fELF": "ELF", b"OggS": "OGG", b"fLaC": "FLAC", b"RIFF": "RIFF",
    b"\x00\x00\x01\x00": "ICO", b"SQLite format 3\x00": "SQLite",
    b"\x28\xb5\x2f\xfd": "ZSTD", b"ustar": "TAR",
}
COMPRESSION = {0: "BI_RGB", 1: "BI_RLE8", 2: "BI_RLE4", 3: "BI_BITFIELDS",
               4: "BI_JPEG", 5: "BI_PNG", 6: "BI_ALPHABITFIELDS"}


def parse_header(d: bytes) -> dict:
    """BITMAPFILEHEADER (14) + DIB (12/40/52/56/108/124) вручную.

    Возвращает словарь с заявленными полями и с посчитанной геометрией:
    rowbytes (с padding до 4 байт), объём пикселей, сколько строк реально есть.
    """
    if len(d) < 18 or d[:2] != b"BM":
        raise ValueError("не BMP: нет магии 'BM'")
    sig, fsize, res1, res2, off = struct.unpack_from("<2sIHHI", d, 0)
    dib = struct.unpack_from("<I", d, 14)[0]
    if dib == 12:                                   # BITMAPCOREHEADER
        w, h, planes, bpp = struct.unpack_from("<HHHH", d, 18)
        compression, imgsz, clrused = 0, 0, 0
        pal_entry = 3
    else:                                           # 40/52/56/108/124
        (w, h, planes, bpp, compression, imgsz,
         xppm, yppm, clrused, clrimp) = struct.unpack_from("<iiHHIIiiII", d, 18)
        pal_entry = 4
    pal_n = (clrused or (1 << bpp)) if bpp <= 8 else 0
    palsize = pal_n * pal_entry
    rowbytes = ((w * bpp + 31) // 32) * 4           # строки выровнены на 4 байта
    rows_decl = abs(h)
    pix_off = off or (14 + dib + palsize)
    rows_real = max(0, (len(d) - pix_off) // rowbytes) if rowbytes else 0
    return {
        "bfSize": fsize, "reserved": [res1, res2], "offbits": off,
        "dib_size": dib, "w": w, "h": h, "topdown": h < 0, "planes": planes,
        "bpp": bpp, "compression": compression,
        "compression_name": COMPRESSION.get(compression, f"?{compression}"),
        "biSizeImage": imgsz, "xppm": xppm if dib != 12 else 0,
        "yppm": yppm if dib != 12 else 0,
        "clrUsed": clrused if dib != 12 else 0,
        "palette_bytes": palsize, "rowbytes": rowbytes,
        "pix_off": pix_off, "rows_declared": rows_decl, "rows_real": rows_real,
        "pixels_declared": rowbytes * rows_decl, "pixels_real": rowbytes * rows_real,
        "file_size": len(d),
    }


def pixel_rows(d: bytes, info: dict, limit: int | None = None) -> list[bytes]:
    """Строки пикселей сверху вниз. BMP с h > 0 хранит их снизу вверх."""
    off, rb = info["pix_off"], info["rowbytes"]
    n = info["rows_real"] if limit is None else min(limit, info["rows_real"])
    rows = [d[off + i * rb: off + (i + 1) * rb] for i in range(n)]
    if info["h"] > 0:
        rows.reverse()
    return rows


def luminance(row: bytes, w: int, bpp: int) -> list[int]:
    """Яркость первых w пикселей строки (для 24/32bpp — по BGR-байтам)."""
    step = max(1, bpp // 8)
    out = []
    for x in range(w):
        i = x * step
        if i + 2 < len(row):
            b, g, r = row[i], row[i + 1], row[i + 2]
            out.append((r * 30 + g * 59 + b * 11) // 100)
        elif i < len(row):
            out.append(row[i])
        else:
            out.append(0)
    return out


def _runs(seq) -> collections.Counter:
    """Длины серий одинаковых соседних элементов — так ловим масштаб пикселя."""
    c, prev, n = collections.Counter(), None, 0
    for v in seq:
        key = tuple(v) if isinstance(v, list) else v
        if key == prev:
            n += 1
        else:
            if prev is not None:
                c[n] += 1
            prev, n = key, 1
    if prev is not None:
        c[n] += 1
    return c


def render_art(rows: list[bytes], info: dict, max_width: int = 190) -> str | None:
    """ASCII-арт области: сначала определяем масштаб пикселя, потом рисуем.

    Так видно текст, нарисованный поверх «пустого» куска: 3x3-растянутый
    пиксельный шрифт превращается в читаемые буквы. None — если область ровная.
    """
    w = info["w"]
    lum = [luminance(r, w, info["bpp"]) for r in rows]
    flat = [v for line in lum for v in line]
    if not flat:
        return None
    lo, hi = min(flat), max(flat)
    if hi - lo < 16:                                # один цвет — смотреть нечего
        return None
    thr = (lo + hi) // 2
    vs = _runs(lum).most_common(1)[0][0] or 1       # вертикальный масштаб
    cols = [[lum[y][x] for y in range(len(lum))] for x in range(w)]
    hs = _runs(cols).most_common(1)[0][0] or 1      # горизонтальный
    vs, hs = max(1, vs), max(1, hs)
    while w // hs > max_width:                      # слишком широко — мельчим
        hs += 1
    grid = []
    for y in range(0, len(lum), vs):
        line = "".join("#" if lum[y][x] > thr else "." for x in range(0, w, hs))
        if line.strip("."):
            grid.append(line)
    return "\n".join(grid) if grid else None


def _magic_ok(data: bytes, i: int, sig: bytes, name: str) -> bool:
    """Правдоподобен ли вложенный файл в позиции i (а не случайные байты).

    В шумных пикселях 'BM' и 'PK\\x03\\x04' встречаются сами по себе, поэтому
    для BMP/ZIP проверяем ещё и поля заголовка.
    """
    rest = data[i:]
    if name == "BMP":
        if len(rest) < 26:
            return False
        fsize, _, _, off = struct.unpack_from("<IHHI", rest, 2)
        dib = struct.unpack_from("<I", rest, 14)[0]
        return (26 <= off <= 1100 and dib in (12, 40, 52, 56, 64, 108, 124)
                and (fsize == 0 or 54 <= fsize <= len(rest)))
    if name.startswith("ZIP"):
        if len(rest) < 10:
            return False
        ver, method = struct.unpack_from("<HH", rest, 4)
        return ver < 64 and method in (0, 8, 9, 12, 14, 93, 95, 98, 99)
    if name == "TAR":
        return len(rest) >= 262 and rest[257:262] == b"ustar"
    return True


def tail_report(d: bytes, info: dict) -> dict:
    """Всё, что лежит после заявленных пикселей: энтропия, сигнатуры, распаковка."""
    rb = info["rowbytes"]
    start = info["pix_off"] + info["pixels_declared"]
    tail = d[start:]
    rep = {"offset": start, "length": len(tail), "rows": None, "entropy": 0.0,
           "unique_bytes": 0, "top": [], "magics": [], "decoded": [],
           "text_preview": "", "art": None, "notes": []}
    if not tail:
        rep["notes"].append("хвоста нет: файл ровно по bfSize")
        return rep
    if rb and len(tail) % rb == 0:
        rep["rows"] = len(tail) // rb
        rep["notes"].append(
            f"хвост = ровно {rep['rows']} строк по {rb} байт → это не «данные», "
            f"а недостающие строки пикселей. Реальная высота {info['rows_real']}, "
            f"в заголовке {info['rows_declared']}")
    cnt = collections.Counter(tail)
    rep["unique_bytes"] = len(cnt)
    rep["top"] = [[b, n] for b, n in cnt.most_common(6)]
    h = -sum(c / len(tail) * math.log2(c / len(tail)) for c in cnt.values())
    rep["entropy"] = round(h, 3)
    for sig, name in MAGICS.items():
        hits = 0
        pos = tail.find(sig)
        while pos >= 0 and hits < 3:
            if _magic_ok(tail, pos, sig, name):
                rep["magics"].append([name, pos, start + pos])
                hits += 1
            pos = tail.find(sig, pos + 1)
    for name, fn in DECODERS.items():
        try:
            out = fn(tail)
        except Exception:
            continue
        if len(out) > 32:
            rep["decoded"].append([name, len(out), out[:64].decode("utf-8", "replace")])
    rep["text_preview"] = "".join(chr(c) if 32 <= c < 127 else "." for c in tail[:80])

    # Рисуем ту область, которой «нет» по заголовку. При bottom-up это первые
    # строки картинки, при top-down — последние.
    extra = info["rows_real"] - info["rows_declared"]
    if extra > 0:
        rows = pixel_rows(d, info)
        rep["art"] = render_art(rows[-extra:] if info["topdown"] else rows[:extra], info)
    elif rep["rows"] is None and len(tail) > 64:
        # хвост не по строкам — пробуем увидеть в нём картинку своей ширины
        width = rb or info["w"] * max(1, info["bpp"] // 8)
        n = len(tail) // width
        if n >= 4:
            fake = {"w": info["w"], "bpp": info["bpp"]}
            rep["art"] = render_art([tail[i * width:(i + 1) * width]
                                     for i in range(min(n, info["rows_real"]))], fake)
    return rep


def plane_report(d: bytes, info: dict, min_score: float = 0.85) -> list[dict]:
    """Bit-plane slicing: каждый бит каждого канала как отдельный поток.

    Смотрим только реальные пиксели (без padding), оба порядка строк, и
    оставляем плоскости, которые похожи на текст, флаг или сжатые данные.
    """
    step = max(1, info["bpp"] // 8)
    names = ("B", "G", "R", "A") if step == 4 else ("B", "G", "R")
    names = names[:step]
    rows = pixel_rows(d, info)
    w = info["w"] * step
    found = []
    for ci, ch in enumerate(names):
        for bit in range(8):
            bits = [(row[ci + k * step] >> bit) & 1
                    for row in rows for k in range(info["w"])]
            ones = sum(bits)
            item = {"channel": ch, "bit": bit, "len": len(bits),
                    "ones": round(ones / max(1, len(bits)), 3),
                    "printable": 0.0, "flags": [], "decoded": [], "uniform": False}
            if ones in (0, len(bits)):
                item["uniform"] = True
                found.append(item)
                continue
            data = bits_to_bytes(bits)
            item["printable"] = round(common.printable_ratio(data), 3)
            item["flags"] = common.find_flags(data)
            for name, fn in DECODERS.items():
                try:
                    out = fn(data)
                except Exception:
                    continue
                if len(out) > 32:
                    item["decoded"].append([name, len(out)])
            found.append(item)
    keep = [i for i in found if not i["uniform"] and
            (i["flags"] or i["decoded"] or
             (i["printable"] >= min_score and i["len"] >= 256))]
    return keep


def bits_to_bytes(bits) -> bytes:
    n = len(bits) // 8 * 8
    if not n:
        return b""
    return int("".join(map(str, bits[:n])), 2).to_bytes(n // 8, "big")


def report(d: bytes, path: str) -> dict:
    """Полный отчёт: заголовок, аномалии, геометрия, признаки стего."""
    info = parse_header(d)
    extra_masks = {3: 12, 6: 16}.get(info["compression"], 0) if info["dib_size"] == 40 else 0
    real = 14 + info["dib_size"] + extra_masks + info["palette_bytes"]
    anomalies = []
    if info["offbits"] != real and info["dib_size"] >= 40:
        anomalies.append(f"bfOffBits {info['offbits']} != 14+dib+палитра {real} "
                         f"(между ними {info['offbits'] - real} байт)")
    if info["bfSize"] != info["file_size"]:
        d_ = info["file_size"] - info["bfSize"]
        anomalies.append(f"bfSize {info['bfSize']} != размер файла "
                         f"{info['file_size']} → лишних {d_} байт")
    need = info["rowbytes"] * info["rows_declared"]
    if info["biSizeImage"] and info["biSizeImage"] != need:
        anomalies.append(f"biSizeImage {info['biSizeImage']} != "
                         f"rowbytes*height = {need}")
    if info["pixels_real"] and info["rows_real"] != info["rows_declared"]:
        anomalies.append(f"реально строк {info['rows_real']}, в заголовке "
                         f"{info['rows_declared']} → {info['rows_real'] - info['rows_declared']} "
                         f"скрытых строк, которых не видно при обычном показе")
    if info["reserved"] != [0, 0]:
        anomalies.append(f"зарезервированные поля не нули: {info['reserved']}")

    grey = None
    if info["bpp"] in (24, 32):
        rows = pixel_rows(d, info, 64)
        px = b"".join(rows)
        st = max(1, info["bpp"] // 8)
        grey = all(px[i] == px[i + 1] == px[i + 2]
                   for i in range(0, len(px) - 2, st))

    notes = []
    if not path.lower().endswith(".bmp"):
        notes.append(f"расширение {os.path.splitext(path)[1] or '—'}, "
                     f"а внутри BMP ({common.human(info['file_size'])})")
    if grey:
        notes.append("картинка серая (R=G=B) → LSB каналов R/G/B одинаковы, "
                     "перебирать каналы бессмысленно")

    return {"file": path, "info": info, "anomalies": anomalies, "notes": notes,
            "grey": grey, "flags": common.find_flags(d)}


def print_report(rep: dict, args) -> None:
    info = rep["info"]
    print(f"[i] {rep['file']} — {common.human(info['file_size'])}")
    print(f"[i] {info['w']}x{info['rows_declared']} (в заголовке), {info['bpp']} bpp, "
          f"{info['compression_name']}, строк снизу вверх: {not info['topdown']}")
    print(f"[i] rowbytes {info['rowbytes']} (padding {info['rowbytes'] - info['w'] * info['bpp'] // 8} "
          f"на строку), пиксели с {info['pix_off']}, палитра {info['palette_bytes']} байт")
    print(f"[i] пикселей по заголовку {info['pixels_declared']}, реально {info['pixels_real']} "
          f"({info['rows_real']} строк)")
    for n in rep["notes"]:
        print(f"[i] {n}")
    if rep["anomalies"]:
        print("\n[!] аномалии заголовка:")
        for a in rep["anomalies"]:
            print("    • " + a)
    else:
        print("\n[+] заголовок согласован с размером файла")
    if rep["flags"]:
        print("\n[+] флаги в сырых байтах:")
        for f in rep["flags"]:
            print("    " + f)


def main() -> None:
    ap = argparse.ArgumentParser(
        description="BMP-стего: разбор заголовка, хвост, битовые плоскости")
    ap.add_argument("file")
    ap.add_argument("--json", action="store_true", help="вывести отчёт как JSON")
    ap.add_argument("--tail", action="store_true",
                    help="разобрать данные после заявленных пикселей: энтропия, "
                         "сигнатуры, распаковка, ASCII-арт")
    ap.add_argument("--planes", action="store_true",
                    help="bit-plane slicing: каждый бит канала как поток")
    ap.add_argument("--min-printable", type=float, default=0.85,
                    help="порог «похоже на текст» для плоскостей (0.85)")
    common.add_flag_args(ap)
    args = ap.parse_args()
    common.apply_flag_args(args)

    try:
        d = open(args.file, "rb").read()
    except (FileNotFoundError, IsADirectoryError, PermissionError) as e:
        print(f"[-] не могу открыть: {e.filename or e}")
        return
    try:
        rep = report(d, args.file)
    except ValueError as e:
        print(f"[-] {e}")
        return

    tail = plane = None
    if args.tail:
        tail = tail_report(d, rep["info"])
    if args.planes:
        plane = plane_report(d, rep["info"], args.min_printable)

    if args.json:
        rep["tail"] = tail
        rep["planes"] = plane
        common.dump_json(rep)
        return

    print_report(rep, args)

    if tail is not None:
        print(f"\n[i] данные после заявленных пикселей: {tail['length']} байт "
              f"с {tail['offset']}")
        if not tail["length"]:
            print("    (нет)")
        else:
            print(f"    энтропия {tail['entropy']} бит/байт, разных байт "
                  f"{tail['unique_bytes']}")
            print(f"    частые байты: " +
                  ", ".join(f"{b:02x}×{n}" for b, n in tail["top"]))
            if tail["rows"]:
                print(f"    = {tail['rows']} целых строк пикселей")
            for n in tail["notes"]:
                print(f"    [i] {n}")
            if tail["magics"]:
                for name, i, abs_off in tail["magics"]:
                    print(f"    [+] вложенный {name} с offset {abs_off} (+{i} от хвоста)")
            else:
                print("    [-] сигнатур вложенных файлов нет")
            if tail["decoded"]:
                for name, n, prev in tail["decoded"]:
                    print(f"    [+] распаковалось как {name}: {n} байт, "
                          f"начало {prev[:48]!r}")
            else:
                print("    [-] zlib/gzip/bz2/lzma не распаковываются")
            print(f"    как текст: {tail['text_preview']}")
            if tail["art"]:
                print("\n[i] ASCII-арт этой области (# = светлое):")
                for line in tail["art"].splitlines():
                    print("    " + line)

    if plane is not None:
        print("\n[i] битовые плоскости (только подозрительные):")
        if not plane:
            print("    нет: все плоскости дают шум, текст или данные не найдены")
        for item in plane:
            tag = "/".join(x for x, _ in item["decoded"]) or "-"
            print(f"    {item['channel']}{item['bit']}: printable "
                  f"{item['printable']}, единиц {item['ones']}, сжатие {tag}, "
                  f"флаги {item['flags'] or '-'}")


if __name__ == "__main__":
    try:
        main()
    except BrokenPipeError:
        pass
    except KeyboardInterrupt:
        print("\n[-] прервано")
