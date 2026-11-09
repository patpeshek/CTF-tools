#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""geo_photo.py — геолокация по фото: EXIF, GPS, ссылки для обратного поиска.

  python geo_photo.py photo.jpg
  python geo_photo.py photo.jpg --json out.json

Скрипт ничего не загружает: он вытаскивает метаданные, считает координаты и
печатает готовые ссылки/чеклист, чтобы дальше искать руками.
"""
from __future__ import annotations

try:
    import sys as _sys
    for _stream in (_sys.stdout, _sys.stderr):
        _stream.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import common  # noqa: E402

TAGS = {
    0x010F: "Make",
    0x0110: "Model",
    0x0112: "Orientation",
    0x0131: "Software",
    0x0132: "DateTime",
    0x9003: "DateTimeOriginal",
    0x829A: "ExposureTime",
    0x829D: "FNumber",
    0x8827: "ISO",
    0x920A: "FocalLength",
    0xA002: "PixelXDimension",
    0xA003: "PixelYDimension",
    0x9286: "UserComment",
}

SEARCH_LINKS = [
    ("Yandex (загрузить фото)", "https://yandex.com/images/"),
    ("Google Lens", "https://lens.google.com/"),
    ("Bing Visual Search", "https://www.bing.com/visualsearch"),
    ("TinEye", "https://tineye.com/"),
]


def to_deg(value):
    try:
        d, m, s = [float(x) for x in value]
        return d + m / 60.0 + s / 3600.0
    except Exception:
        return None


def gps_of(exif):
    try:
        gps = exif.get_ifd(0x8825)
    except Exception:
        return None
    if not gps:
        return None
    lat = to_deg(gps.get(2))
    lon = to_deg(gps.get(4))
    if lat is None or lon is None:
        return None
    if str(gps.get(1, "N")).upper().startswith("S"):
        lat = -lat
    if str(gps.get(3, "E")).upper().startswith("W"):
        lon = -lon
    alt = gps.get(6)
    return {"lat": round(lat, 6), "lon": round(lon, 6),
            "alt": (alt[0] / alt[1]) if isinstance(alt, tuple) and alt[1] else None}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("file")
    ap.add_argument("--json", help="сохранить отчёт в JSON")
    common.add_flag_args(ap)
    args = ap.parse_args()
    common.apply_flag_args(args)

    if not os.path.isfile(args.file):
        print(f"[-] нет файла: {args.file}")
        return
    try:
        from PIL import Image
    except ImportError:
        print("[-] нет Pillow")
        return
    try:
        img = Image.open(args.file)
    except Exception as e:
        print(f"[-] не открыть картинку: {e}")
        return

    exif = img.getexif()
    meta = {}
    for tag, name in TAGS.items():
        try:
            value = exif.get(tag)
        except Exception:
            value = None
        if value not in (None, "", b""):
            meta[name] = str(value)[:200]
    gps = gps_of(exif) if exif else None

    print(f"[i] файл: {os.path.basename(args.file)}  {img.width}x{img.height}  {img.format}")
    if meta:
        print("\n=== EXIF ===")
        for k, v in meta.items():
            print(f"  {k}: {v}")
    else:
        print("[i] EXIF пуст (или его вырезали)")

    if gps:
        print(f"\n=== GPS ===\n  {gps['lat']}, {gps['lon']}"
              + (f"  (высота {gps['alt']:.0f} м)" if gps.get("alt") else ""))
        print(f"  OSM:    https://www.openstreetmap.org/?mlat={gps['lat']}&mlon={gps['lon']}#map=16/{gps['lat']}/{gps['lon']}")
        print(f"  Google: https://maps.google.com/?q={gps['lat']},{gps['lon']}")
        print(f"  Yandex: https://yandex.ru/maps/?ll={gps['lon']}%2C{gps['lat']}&z=16")
    else:
        print("\n[i] GPS в EXIF нет — искать по картинке")

    print("\n=== обратный поиск (загрузить фото руками) ===")
    for name, url in SEARCH_LINKS:
        print(f"  {name}: {url}")

    print("\n=== чеклист без EXIF ===")
    for line in (
        "язык и шрифт вывесок, телефонные коды, форма номеров",
        "дорожные знаки, разметка, сторона движения",
        "архитектура, материалы, крыши, окна",
        "растительность, рельеф, грунт",
        "тени: направление и длина (SunCalc) → время и сторона света",
        "отражения в витринах, номера машин, названия магазинов",
        "метаданные мессенджеров: имена файлов, превью, «геометки»",
    ):
        print(f"  - {line}")

    for f in common.find_flags((meta.get("UserComment", "") + " " +
                                meta.get("Software", "")).encode("utf-8", "replace")):
        print(f"[!!!] ФЛАГ: {f}")

    if args.json:
        report = {"file": os.path.abspath(args.file), "size": [img.width, img.height],
                  "exif": meta, "gps": gps,
                  "links": dict(SEARCH_LINKS)}
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(report, fh, ensure_ascii=False, indent=1)
        print(f"\n[i] отчёт: {args.json}")


if __name__ == "__main__":
    main()
