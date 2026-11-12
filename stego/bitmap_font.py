#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
bitmap_font.py — из списка точек собрать картинку и разобрать её на глифы.

  python bitmap_font.py points.csv
  python bitmap_font.py points.csv --ascii --png out.png
  python bitmap_font.py points.csv --decode          # встроенный шрифт 5x5
  python bitmap_font.py points.csv --font myfont.json

CSV: строки "x,y" или "x,y,value" (value != 0 считается закрашенной точкой).
Шрифт JSON: {"A": ["01110", "10001", ...], ...} — 5 строк по 5 символов.
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

FONT5 = {
    "0": ["01110", "10001", "10001", "10001", "01110"],
    "1": ["00100", "01100", "00100", "00100", "01110"],
    "2": ["01110", "10001", "00001", "00010", "11111"],
    "3": ["11110", "00001", "00110", "00001", "11110"],
    "4": ["00010", "00110", "01010", "11111", "00010"],
    "5": ["11111", "10000", "11110", "00001", "11110"],
    "6": ["01110", "10000", "11110", "10001", "01110"],
    "7": ["11111", "00001", "00010", "00100", "00100"],
    "8": ["01110", "10001", "01110", "10001", "01110"],
    "9": ["01110", "10001", "01111", "00001", "01110"],
    "A": ["01110", "10001", "11111", "10001", "10001"],
    "B": ["11110", "10001", "11110", "10001", "11110"],
    "C": ["01111", "10000", "10000", "10000", "01111"],
    "D": ["11110", "10001", "10001", "10001", "11110"],
    "E": ["11111", "10000", "11110", "10000", "11111"],
    "F": ["11111", "10000", "11110", "10000", "10000"],
    "G": ["01111", "10000", "10111", "10001", "01111"],
    "H": ["10001", "10001", "11111", "10001", "10001"],
    "I": ["11111", "00100", "00100", "00100", "11111"],
    "J": ["00111", "00010", "00010", "10010", "01100"],
    "K": ["10001", "10010", "11100", "10010", "10001"],
    "L": ["10000", "10000", "10000", "10000", "11111"],
    "M": ["10001", "11011", "10101", "10001", "10001"],
    "N": ["10001", "11001", "10101", "10011", "10001"],
    "O": ["01110", "10001", "10001", "10001", "01110"],
    "P": ["11110", "10001", "11110", "10000", "10000"],
    "Q": ["01110", "10001", "10101", "10010", "01101"],
    "R": ["11110", "10001", "11110", "10010", "10001"],
    "S": ["01111", "10000", "01110", "00001", "11110"],
    "T": ["11111", "00100", "00100", "00100", "00100"],
    "U": ["10001", "10001", "10001", "10001", "01110"],
    "V": ["10001", "10001", "10001", "01010", "00100"],
    "W": ["10001", "10001", "10101", "11011", "10001"],
    "X": ["10001", "01010", "00100", "01010", "10001"],
    "Y": ["10001", "01010", "00100", "00100", "00100"],
    "Z": ["11111", "00010", "00100", "01000", "11111"],
    "{": ["00110", "01000", "01100", "01000", "00110"],
    "}": ["01100", "00010", "00110", "00010", "01100"],
    "_": ["00000", "00000", "00000", "00000", "11111"],
    "-": ["00000", "00000", "11111", "00000", "00000"],
}

# Вариант шрифта, который встречается на «пиксель-арт» холстах: цифры и hex-буквы
# нарисованы иначе (наклонные, узкая 1 и фигурные скобки 3px). Обновляем базу,
# чтобы автодекод не путал 4 с '-', 1 с '_' и т.п.
FONT5.update({
    "0": [".###.", "#..##", "#.#.#", "##..#", ".###."],
    "1": [".#.", "##.", ".#.", ".#.", "###"],
    "2": [".###.", "#...#", "..##.", ".#...", "#####"],
    "3": ["####.", "....#", ".###.", "....#", "####."],
    "4": ["#..#.", "#..#.", "#####", "...#.", "...#."],
    "5": ["#####", "#....", "####.", "....#", "####."],
    "6": [".###.", "#....", "####.", "#...#", ".###."],
    "7": ["#####", "....#", "...#.", "..#..", "..#.."],
    "8": [".###.", "#...#", ".###.", "#...#", ".###."],
    "9": [".###.", "#...#", ".####", "....#", ".###."],
    "A": [".###.", "#...#", "#####", "#...#", "#...#"],
    "B": ["####.", "#...#", "####.", "#...#", "####."],
    "C": [".####", "#....", "#....", "#....", ".####"],
    "D": ["####.", "#...#", "#...#", "#...#", "####."],
    "E": ["#####", "#....", "####.", "#....", "#####"],
    "F": ["#####", "#....", "####.", "#....", "#...."],
    "{": [".##", ".#.", "##.", ".#.", ".##"],
    "}": ["##.", ".#.", ".##", ".#.", "##."],
})


def read_points(path):
    pts = set()
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or line.lower().startswith("x,y"):
                continue
            parts = line.replace(";", ",").replace("\t", ",").split(",")
            if len(parts) < 2:
                continue
            try:
                x, y = int(float(parts[0])), int(float(parts[1]))
            except (ValueError, OverflowError):     # мусор, nan, inf
                continue
            v = 1
            if len(parts) > 2:
                try:
                    v = float(parts[2])
                except ValueError:
                    v = 1
            if v:
                pts.add((x, y))
    return pts


MAX_CELLS = 4_000_000   # предел холста w*h (сетка списков + проход по всем клеткам)
GAP = 3                 # столько пустых колонок/строк остаётся от большого разрыва


def squeeze(vals, gap=GAP):
    """Монотонно сжать координаты: разрыв больше gap пустых клеток → gap.
    Соседство точек и пустые колонки между глифами сохраняются."""
    m, cur, prev = {}, 0, None
    for v in sorted(set(vals)):
        if prev is not None:
            cur += min(v - prev, gap + 1)
        m[v] = cur
        prev = v
    return m


def fit_points(pts, max_cells=MAX_CELLS):
    """Далёкие/огромные координаты не должны раздувать холст до гигабайт.

    Возвращает (точки, замечание); точки None — не влезло даже после сжатия.
    """
    xs = {x for x, _ in pts}
    ys = {y for _, y in pts}
    w, h = max(xs) - min(xs) + 1, max(ys) - min(ys) + 1
    if w * h <= max_cells:
        return pts, None
    mx, my = squeeze(xs), squeeze(ys)
    w2, h2 = max(mx.values()) + 1, max(my.values()) + 1
    note = (f"холст {w}x{h} слишком большой — пустые промежутки сжаты "
            f"до {GAP}: {w2}x{h2}")
    if w2 * h2 > max_cells:
        return None, note + f", всё равно больше {max_cells} клеток"
    return {(mx[x], my[y]) for x, y in pts}, note


def build_grid(pts, pad=0, flip_y=False, flip_x=False):
    xs = [p[0] for p in pts]
    ys = [p[1] for p in pts]
    x0, x1 = min(xs) - pad, max(xs) + pad
    y0, y1 = min(ys) - pad, max(ys) + pad
    w, h = x1 - x0 + 1, y1 - y0 + 1
    g = [[0] * w for _ in range(h)]
    for x, y in pts:
        cx = (x1 - x) if flip_x else (x - x0)
        cy = (y1 - y) if flip_y else (y - y0)
        g[cy][cx] = 1
    return g, x0, y0, w, h


def segment(glyphs_grid):
    """Делит по пустым столбцам; возвращает список (start, end) и сами матрицы."""
    h = len(glyphs_grid)
    w = len(glyphs_grid[0])
    cols = [any(glyphs_grid[y][x] for y in range(h)) for x in range(w)]
    out, start = [], None
    for x, filled in enumerate(cols):
        if filled and start is None:
            start = x
        elif not filled and start is not None:
            out.append((start, x))
            start = None
    if start is not None:
        out.append((start, w))
    return out


def pattern_of(g, s, e):
    return tuple("".join("#" if g[y][x] else "." for x in range(s, e)) for y in range(len(g)))


def hamming(a, b):
    # сравниваем по общей ширине, добивая пробелами; 1/#/█ считаем закрашенным
    def on(c):
        return c in "#1\u2588"
    w = max(len(a[0]), len(b[0]))
    dist = 0
    for y in range(5):
        ra = a[y].ljust(w, ".")
        rb = b[y].ljust(w, ".")
        dist += sum(1 for i in range(w) if on(ra[i]) != on(rb[i]))
    return dist


def decode(glyphs, font):
    out = []
    for pat in glyphs:
        best, dist = "?", 10 ** 9
        for ch, rows in font.items():
            d = hamming(pat, rows)
            if d < dist:
                best, dist = ch, d
        out.append(best)
    return "".join(out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("csv")
    ap.add_argument("--ascii", action="store_true")
    ap.add_argument("--png")
    ap.add_argument("--scale", type=int, default=4)
    ap.add_argument("--decode", action="store_true")
    ap.add_argument("--font")
    ap.add_argument("--legend", action="store_true", help="показать уникальные глифы")
    ap.add_argument("--flip-y", action="store_true", help="отразить по вертикали (Y растёт вверх)")
    ap.add_argument("--flip-x", action="store_true")
    ap.add_argument("--lower", action="store_true", help="перевести буквы в нижний регистр")
    ap.add_argument("--export-font", help="известный текст: сохранить глифы как JSON-шрифт")
    ap.add_argument("--font-out", default="font.json")
    args = ap.parse_args()

    pts = read_points(args.csv)
    if not pts:
        print("[-] точек не найдено")
        return
    pts, note = fit_points(pts)
    if note:
        print(f"[!] {note}")
    if pts is None:
        return
    g, x0, y0, w, h = build_grid(pts, flip_y=args.flip_y, flip_x=args.flip_x)
    print(f"[+] холст: {w}x{h}  (x0={x0}, y0={y0}), точек={len(pts)}")

    if args.ascii:
        for row in g:
            print("".join("#" if v else "." for v in row))

    segs = segment(g)
    glyphs = [pattern_of(g, s, e) for s, e in segs]
    print(f"[+] глифов: {len(glyphs)}")

    if args.legend:
        uniq = {}
        for pat in glyphs:
            uniq.setdefault(pat, len(uniq))
        for pat, idx in uniq.items():
            print(f"\nG{idx}:")
            for row in pat:
                print("  " + row.replace("#", "██").replace(".", "  "))
        print("\nпоследовательность:", " ".join(f"G{uniq[p]}" for p in glyphs))

    if args.decode:
        font = FONT5
        if args.font:
            font = json.load(open(args.font, encoding="utf-8"))
        text = decode(glyphs, font)
        if args.lower:
            text = text.lower()
        print("[+] decode:", text)

    if args.export_font:
        if len(args.export_font) != len(glyphs):
            print(f"[!] в тексте {len(args.export_font)} символов, глифов {len(glyphs)} — "
                  "лишние будут отброшены")
        font = {}
        for ch, pat in zip(args.export_font, glyphs):
            font[ch] = list(pat)
        json.dump(font, open(args.font_out, "w", encoding="utf-8"),
                  ensure_ascii=False, indent=2)
        print(f"[+] шрифт сохранён: {args.font_out} ({len(font)} глифов)")

    if args.png:
        from PIL import Image
        s = args.scale
        img = Image.new("RGB", (w * s, h * s), (255, 255, 255))
        px = img.load()
        for y in range(h):
            for x in range(w):
                if g[y][x]:
                    for dy in range(s):
                        for dx in range(s):
                            px[x * s + dx, y * s + dy] = (0, 0, 0)
        img.save(args.png)
        print(f"[+] PNG: {args.png}")


if __name__ == "__main__":
    try:
        main()
    except (FileNotFoundError, IsADirectoryError, PermissionError) as e:
        print(f"[-] не могу открыть: {getattr(e, 'filename', None) or e}")
    except BrokenPipeError:
        pass
    except KeyboardInterrupt:
        print("\n[-] прервано")
