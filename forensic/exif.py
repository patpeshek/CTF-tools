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
import shutil
import subprocess

KEYS = ["DateTimeOriginal", "CreateDate", "ModifyDate", "Make", "Model", "LensModel",
        "SerialNumber", "Software", "Artist", "Author", "GPSLatitude", "GPSLongitude",
        "GPSAltitude", "XResolution", "YResolution", "ImageWidth", "ImageHeight"]


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


def via_pil(path, show_all):
    from PIL import Image
    im = Image.open(path)
    ex = im.getexif()
    data = {"Format": im.format, "Size": im.size, "Mode": im.mode}
    if ex:
        from PIL.ExifTags import TAGS
        for k, v in ex.items():
            name = TAGS.get(k, str(k))
            if show_all or name in KEYS:
                data[name] = str(v)
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
