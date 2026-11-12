#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
exif.py — метаданные картинки/файла. Использует exiftool, если он есть,
иначе PIL (для JPEG/PNG/TIFF).

  python exif.py photo.jpg
  python exif.py photo.jpg --all
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
import json
import os
import shutil
import subprocess
import sys

KEYS = ["DateTimeOriginal", "CreateDate", "ModifyDate", "Make", "Model", "LensModel",
        "SerialNumber", "Software", "Artist", "Author", "GPSLatitude", "GPSLongitude",
        "GPSAltitude", "XResolution", "YResolution", "ImageWidth", "ImageHeight",
        # текстовые поля, где обычно прячут флаг
        "ImageDescription", "UserComment", "Comment", "Copyright",
        "XPTitle", "XPComment", "XPAuthor", "XPKeywords", "XPSubject",
        "GPSPosition"]
XP_TAGS = {"XPTitle", "XPComment", "XPAuthor", "XPKeywords", "XPSubject"}
IFD_POINTERS = {0x8769, 0x8825, 0xA005}     # ExifOffset, GPSInfo, Interop


def via_exiftool(path, show_all):
    exe = shutil.which("exiftool") or shutil.which("ExifTool")
    if not exe:
        return None
    out = subprocess.run([exe, "-j", "-G", path], capture_output=True, text=True)
    try:
        data = json.loads(out.stdout)[0]
    except Exception:
        return None
    if show_all:
        return data
    return {k: v for k, v in data.items() if any(k.endswith(x) or x in k for x in KEYS)}


def _text(v):
    """bytes -> строка, если это похоже на текст; иначе repr."""
    if not isinstance(v, bytes):
        return str(v)
    s = v.rstrip(b"\x00").decode("utf-8", "replace")
    if s and sum(ch.isprintable() or ch in "\r\n\t" for ch in s) / len(s) > 0.9:
        return s
    return repr(v[:200])


def _value(name, v):
    if name in XP_TAGS and isinstance(v, (bytes, tuple)):
        # XP*: UTF-16LE в BYTE-массиве
        return bytes(v).decode("utf-16-le", "replace").rstrip("\x00")
    if name == "UserComment" and isinstance(v, bytes):
        head, body = v[:8], v[8:]
        if head.startswith(b"UNICODE"):
            # порядок байт не помечен: берём вариант, где больше ASCII
            cands = [body.decode(c, "replace").rstrip("\x00")
                     for c in ("utf-16-le", "utf-16-be")]
            return max(cands, key=lambda s: sum(ch.isascii() for ch in s))
        if head.startswith((b"ASCII", b"\x00" * 8, b"JIS")):
            return _text(body).strip()
        return _text(v)
    return _text(v)


def _gps_position(ex):
    """Десятичные координаты — парсер из geo_photo.py."""
    try:
        sys.path.append(os.path.dirname(os.path.abspath(__file__)))
        from geo_photo import gps_of
        g = gps_of(ex)
    except Exception:
        return None
    return f"{g['lat']}, {g['lon']}" if g else None


def via_pil(path, show_all):
    from PIL import Image
    from PIL.ExifTags import GPSTAGS, TAGS
    im = Image.open(path)
    ex = im.getexif()
    data = {"Format": im.format, "Size": im.size, "Mode": im.mode}

    def put(name, v):
        if show_all or name in KEYS:
            data[name if name not in data else f"{name}#2"] = _value(name, v)

    if ex:
        for k, v in ex.items():                       # IFD0
            if k not in IFD_POINTERS:
                put(TAGS.get(k, str(k)), v)
        for ptr in (0x8769, 0xA005):                  # Exif sub-IFD, Interop
            try:
                for k, v in ex.get_ifd(ptr).items():
                    put(TAGS.get(k, str(k)), v)
            except Exception:
                pass
        try:
            for k, v in ex.get_ifd(0x8825).items():   # GPS IFD
                put(GPSTAGS.get(k, f"GPS{k}"), v)
        except Exception:
            pass
        pos = _gps_position(ex)
        if pos:
            put("GPSPosition", pos)
    # JPEG COM (может быть несколько), PNG/GIF comment
    coms = [p for seg, p in getattr(im, "applist", []) if seg == "COM"]
    if not coms and isinstance(im.info.get("comment"), (bytes, str)):
        coms = [im.info["comment"]]
    for c in coms:
        put("Comment", c)
    return data


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("file")
    ap.add_argument("--all", action="store_true")
    args = ap.parse_args()

    data = via_exiftool(args.file, args.all)
    if data is None:
        try:
            data = via_pil(args.file, args.all)
        except Exception as e:
            print(f"[-] не смог прочитать метаданные: {e}")
            return
    for k, v in data.items():
        print(f"{k:28s} {v}")


if __name__ == "__main__":
    main()
