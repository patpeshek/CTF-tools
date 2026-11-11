#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
jpeg_tail.py — найти хвост после JPEG (EOI = FF D9) и вытащить вложенное.

  python jpeg_tail.py image1.jpg
  python jpeg_tail.py image1.jpg --dump tail.bin
  python jpeg_tail.py image1.jpg --extract out_dir

Часто после EOI пришит ZIP (сигнатура PK\\x03\\x04) с паролем из текста задачи.
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
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from carve import jpeg_end  # noqa: E402  (разбор по маркерам — общий с carve)

SIGS = {
    b"PK\x03\x04": ".zip",
    b"\x89PNG\r\n\x1a\n": ".png",
    b"\xff\xd8\xff": ".jpg",
    b"%PDF": ".pdf",
    b"\x1f\x8b": ".gz",
    b"7z\xbc\xaf\x27\x1c": ".7z",
    b"Rar!\x1a\x07": ".rar",
}


def find_eoi(data: bytes) -> int:
    """Конец первого JPEG по маркерам: сегменты до SOS по длинам (FFD9
    миниатюры в APP1 пропускается), потом энтропийные данные с учётом
    FF00/RSTn. Последнее FF D9 не годится: JPEG+JPEG даёт «хвоста нет»,
    а FFD9 внутри приклеенного ZIP сдвигает хвост."""
    if data.startswith(b"\xff\xd8"):
        end = jpeg_end(data, 0)
        if end != -1:
            return end
        print("[!] маркеры JPEG не разобрались — беру последнее FF D9")
    pos = data.rfind(b"\xff\xd9")
    return pos + 2 if pos != -1 else -1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("image")
    ap.add_argument("--dump", help="куда сохранить хвост")
    ap.add_argument("--extract", help="папка: распаковать ZIP-хвост")
    args = ap.parse_args()

    data = open(args.image, "rb").read()
    if not data.startswith(b"\xff\xd8\xff"):
        print("[!] это не JPEG (нет SOI). Всё равно ищу FFD9...")

    end = find_eoi(data)
    print(f"[+] размер файла: {len(data)}")
    print(f"[+] конец JPEG (EOI) на смещении: {end}")
    if end == -1 or end >= len(data):
        print("[-] хвоста нет")
        return

    tail = data[end:]
    print(f"[+] хвост: {len(tail)} байт")
    print("[+] первые 32 байта:", tail[:32].hex())
    kind = next((ext for sig, ext in SIGS.items() if tail.startswith(sig)), None)
    print("[+] тип хвоста:", kind or "неизвестен")

    if args.dump:
        open(args.dump, "wb").write(tail)
        print(f"[+] сохранено: {args.dump}")

    if kind == ".zip" and args.extract:
        os.makedirs(args.extract, exist_ok=True)
        import zipfile
        try:
            with zipfile.ZipFile(__import__("io").BytesIO(tail)) as z:
                print("[+] файлы в ZIP:", z.namelist())
                z.extractall(args.extract)
                print(f"[+] распаковано в {args.extract}")
        except Exception as e:
            print(f"[!] ZIP не открылся: {e} (возможно, нужен пароль или хвост обрезан)")


if __name__ == "__main__":
    try:
        main()
    except (FileNotFoundError, IsADirectoryError, PermissionError) as e:
        print(f"[-] не могу открыть: {getattr(e, 'filename', None) or e}")
    except BrokenPipeError:
        pass
    except KeyboardInterrupt:
        print("\n[-] прервано")
