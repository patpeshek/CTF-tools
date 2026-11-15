#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
rtf_gaps.py - полезная нагрузка в пробельных "хвостах" RTF/текста: серии и зазоры.

Идея: в RTF пробел после control word - разделитель, таб - значимый символ.
Поэтому длинные хвосты из пробелов/табов после control word - классическое
место для стега. Скрипт вынимает такие хвосты, режет их на "серии"
(k пробелов + таб) и прогоняет все ходовые раскладки:

  bits      space=0/tab=1 -> байты: порядок бит, инверсия по строкам,
            реверс хвоста/строк/всего потока, сдвиг 0..7
  gaps      длина серии (0..7) -> 3 бита: по потоку, по столбцам,
            битовые плоскости, выброс первого/последнего токена
  unary     серия = k нулей + 1

Плюс диагностика: распределение длин серий (chi2 на равномерность),
доля табов и сравнение с ожидаемой долей единиц для текста.

  python rtf_gaps.py file.rtf
  python rtf_gaps.py file.rtf --json
  python rtf_gaps.py file.rtf --verbose --min-run 4
  python rtf_gaps.py file.rtf --pattern "flag\\{[^}]+\\}"

Коды возврата: 0 - флаг найден, 1 - не найден.
"""
from __future__ import annotations

# Windows: консоль/pipe не любит Unicode (-, —, <>).
try:
    import sys as _sys
    for _stream in (_sys.stdout, _sys.stderr):
        _stream.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

import argparse
import json
import re
import sys

WS = " \t"
DEFAULT_PATTERN = r"[A-Za-z0-9_]{1,12}\{[ -~]{2,120}\}"


# ---------------- извлечение ----------------

def read_file(path: str) -> bytes:
    with open(path, "rb") as fh:
        return fh.read()


def find_runs(text: str, min_run: int = 4):
    """Максимальные серии пробелов/табов длиной >= min_run."""
    runs = []
    for m in re.finditer(r"[ \t]{%d,}" % max(1, min_run), text):
        chunk = m.group()
        line_no = text.count("\n", 0, m.start())
        runs.append({
            "offset": m.start(),
            "line": line_no,
            "text": chunk,
            "len": len(chunk),
            "spaces": chunk.count(" "),
            "tabs": chunk.count("\t"),
            "gaps": [len(g) for g in chunk.split("\t")],
        })
    return runs


def bits_of(run_text: str, tab_is_one: bool = True):
    """space/tab -> биты."""
    zero, one = (" ", "\t") if tab_is_one else ("\t", " ")
    return [1 if c == one else 0 for c in run_text if c in WS]


def pack(bits, msb: bool = True, shift: int = 0) -> bytes:
    """Биты -> байты. msb=False - младший бит в байте первым."""
    out = bytearray()
    for i in range(shift, len(bits) - 7, 8):
        chunk = bits[i:i + 8]
        if not msb:
            chunk = chunk[::-1]
        v = 0
        for x in chunk:
            v = (v << 1) | x
        out.append(v)
    return bytes(out)


def values_to_bits(values, width: int = 3, msb: bool = True):
    bits = []
    lim = (1 << width) - 1
    for v in values:
        if v > lim:
            continue
        order = range(width - 1, -1, -1) if msb else range(width)
        bits.extend((v >> k) & 1 for k in order)
    return bits


# ---------------- раскладки ----------------

def _mask_list(n, full_masks=True):
    """Маски инверсии по строкам. full - все 2**n (для <=10 строк)."""
    if full_masks and n <= 10:
        return list(range(1 << n))
    even = sum(1 << i for i in range(0, n, 2))
    odd = sum(1 << i for i in range(1, n, 2))
    return [0, (1 << n) - 1, even, odd, even ^ odd]


def bit_variants(runs, tab_is_one=True, full_masks=True, trims=(0, 1, 2, 3)):
    """(имя, биты) для space/tab-потока.

    trims: сколько символов с конца каждого хвоста отбросить (случайный
    паддинг, как в рукописных генераторах).
    """
    base = [bits_of(r["text"], tab_is_one) for r in runs]
    n = len(base)

    for t in trims:
        chunks = [c[:len(c) - t] if t else c for c in base]
        tag = "" if t == 0 else ", хвост -%d" % t
        if not any(chunks):
            continue

        yield "поток вперёд" + tag, [b for c in chunks for b in c]
        yield "поток назад" + tag, [b for c in chunks[::-1] for b in c]

        masks = _mask_list(n, full_masks)
        for mask in masks:
            if mask == 0:
                continue
            bits = []
            for i, c in enumerate(chunks):
                inv = (mask >> i) & 1
                bits.extend(x ^ inv for x in c)
            yield "инверсия строк mask=%d%s" % (mask, tag), bits

    chunks = base

    # реверс каждого хвоста отдельно
    rev = [b for c in chunks for b in c[::-1]]
    yield "реверс каждого хвоста", rev
    yield "реверс каждого хвоста + инверсия", [x ^ 1 for x in rev]

    # по столбцам (как будто хвосты - строки матрицы)
    mx = max(len(c) for c in chunks)
    col = [c[r] for r in range(mx) for c in chunks if r < len(c)]
    yield "по столбцам", col
    yield "по столбцам назад", col[::-1]


def gap_variants(runs):
    """(имя, биты) для длин серий, закодированных 3 битами."""
    flat = [g for r in runs for g in r["gaps"]]
    if not flat:
        return
    for drop, tag in ((0, "все"), (1, "без первого"), (len(flat) - 1, "без последнего")):
        vals = flat[drop:] if drop == 0 else (flat[drop + 1:] if drop == 1 else flat[:drop])
        if len(vals) < 3:
            continue
        for msb in (True, False):
            yield "серии %s, 3 бита %s" % (tag, "MSB" if msb else "LSB"), values_to_bits(vals, 3, msb)
        # битовые плоскости
        for order in ((2, 1, 0), (0, 1, 2)):
            planes = []
            for k in order:
                planes.extend((v >> k) & 1 for v in vals)
            yield "серии %s, плоскости %s" % (tag, order), planes
        # по столбцам
        cols = [r["gaps"] for r in runs]
        mx = max(len(c) for c in cols)
        col = [c[rr] for rr in range(mx) for c in cols if rr < len(c)]
        yield "серии %s, по столбцам" % tag, values_to_bits(col, 3, True)


def unary_variants(runs):
    flat = [g for r in runs for g in r["gaps"]]
    if not flat:
        return
    bits = []
    for v in flat:
        bits.extend([0] * v + [1])
    yield "унарно (k нулей + 1)", bits
    yield "унарно инверсно", [x ^ 1 for x in bits]


# ---------------- диагностика ----------------

def find_flags(data: bytes, pattern: str):
    rx = re.compile(pattern.encode("latin-1", "replace"))
    return [m.group().decode("latin-1") for m in rx.finditer(data)]


def chi2_uniform(values, k=8):
    n = len(values)
    if n == 0:
        return 0.0, {}
    hist = {v: values.count(v) for v in set(values)}
    exp = n / k
    chi = sum((hist.get(v, 0) - exp) ** 2 / exp for v in range(k))
    return chi, hist


def printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    return sum(32 <= c < 127 or c in (9, 10, 13) for c in data) / len(data)


def text_score(data: bytes) -> float:
    """Грубая оценка "похоже на текст": печатность + доля букв."""
    if not data:
        return 0.0
    pr = printable_ratio(data)
    letters = sum(chr(c).isalpha() for c in data if 32 <= c < 127) / len(data)
    spaces = data.count(b" ") / len(data)
    return pr + 0.5 * letters + 0.3 * (1.0 if 0.05 < spaces < 0.30 else 0.0)


# ---------------- основной разбор ----------------

def analyze(path: str, min_run: int = 4, pattern: str = DEFAULT_PATTERN,
            verbose: bool = False, full_masks: bool = True,
            trims=(0, 1, 2, 3)):
    raw = read_file(path)
    text = raw.decode("latin-1")
    runs = find_runs(text, min_run)
    result = {
        "file": path,
        "bytes": len(raw),
        "runs": [{k: r[k] for k in ("offset", "line", "len", "spaces", "tabs", "gaps")}
                 for r in runs],
        "totals": {
            "runs": len(runs),
            "chars": sum(r["len"] for r in runs),
            "spaces": sum(r["spaces"] for r in runs),
            "tabs": sum(r["tabs"] for r in runs),
            "tokens": sum(len(r["gaps"]) for r in runs),
        },
        "attempts": [],
        "findings": [],
    }
    if not runs:
        result["verdict"] = "пробельных хвостов не найдено"
        return result

    # диагностика длин серий
    flat = [g for r in runs for g in r["gaps"]]
    chi, hist = chi2_uniform(flat)
    tab_share = result["totals"]["tabs"] / max(1, result["totals"]["chars"])
    result["diagnostics"] = {
        "gap_chi2": round(chi, 2),
        "gap_hist": {str(k): hist.get(k, 0) for k in range(8)},
        "gap_uniform_like": chi < 14.07,   # df=7, 5%
        "tab_share": round(tab_share, 3),
        "expected_tab_share_text": "0.35-0.50",
    }

    # перебор
    best = None
    seen = set()
    seen_names = 0
    for family, gen in (("bits", lambda r: bit_variants(r, full_masks=full_masks,
                                                        trims=trims)),
                        ("gaps", gap_variants),
                        ("unary", unary_variants)):
        for name, bits in gen(runs):
            key = (family, hash(tuple(bits)))
            if key in seen:
                continue
            seen.add(key)
            seen_names += 1
            for msb in (True, False):
                for shift in range(8):
                    data = pack(bits, msb, shift)
                    if not data:
                        continue
                    flags = find_flags(data, pattern)
                    for f in flags:
                        entry = {"family": family, "variant": name, "msb": msb,
                                 "shift": shift, "flag": f,
                                 "preview": data[:80].decode("latin-1")}
                        result["findings"].append(entry)
                        if verbose:
                            print("[!] %s / %s msb=%s shift=%d -> %s"
                                  % (family, name, msb, shift, f))
                    sc = text_score(data)
                    if best is None or sc > best["score"]:
                        best = {"family": family, "variant": name, "msb": msb,
                                "shift": shift, "score": round(sc, 3),
                                "preview": data[:120].decode("latin-1")}

    result["attempts"] = seen_names
    result["best_candidate"] = best
    if result["findings"]:
        result["verdict"] = "флаг найден (%d совпадений)" % len(result["findings"])
    elif result["diagnostics"]["gap_uniform_like"] and tab_share < 0.30:
        result["verdict"] = ("похоже на случайный паддинг: серии равномерны (chi2=%.2f), "
                             "доля табов %.2f - битового потока текста тут не помещается"
                             % (chi, tab_share))
    else:
        result["verdict"] = "флага нет ни в одной из %d раскладок" % seen_names
    return result


def print_human(res):
    print("\n[файл] %s  %d байт" % (res["file"], res["bytes"]))
    t = res["totals"]
    print("[хвосты] строк=%d символов=%d (пробелов %d, табов %d), токенов=%d"
          % (t["runs"], t["chars"], t["spaces"], t["tabs"], t["tokens"]))
    print("\n%4s %6s %5s %5s  %s" % ("#", "длина", "проб", "таб", "серии «k пробелов + таб»"))
    for i, r in enumerate(res["runs"], 1):
        print("%4d %6d %5d %5d  %s" % (i, r["len"], r["spaces"], r["tabs"], r["gaps"]))
    if "diagnostics" in res:
        d = res["diagnostics"]
        print("\n[диагностика] chi2 длин серий=%s  (df=7, порог 14.07)  -> %s"
              % (d["gap_chi2"], "равномерно/шум" if d["gap_uniform_like"] else "есть структура"))
        print("              доли 0..7: %s" % d["gap_hist"])
        print("              доля табов=%.2f (для текста ждём %s)"
              % (d["tab_share"], d["expected_tab_share_text"]))
    if res.get("best_candidate"):
        b = res["best_candidate"]
        print("\n[лучший кандидат] %s / %s msb=%s shift=%d score=%.2f"
              % (b["family"], b["variant"], b["msb"], b["shift"], b["score"]))
        print("  %r" % b["preview"])
    if res["findings"]:
        print("\n[!] НАЙДЕНО:")
        for f in res["findings"]:
            print("  %s   (%s / %s)" % (f["flag"], f["family"], f["variant"]))
    else:
        print("\n[-] флаг не найден (перебрано раскладок: %d)" % res["attempts"])
    print("[итог] %s" % res["verdict"])


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Стегано в пробельных хвостах RTF/текста: серии, зазоры, декодеры.")
    ap.add_argument("file")
    ap.add_argument("--json", action="store_true", help="машинный вывод")
    ap.add_argument("--verbose", action="store_true", help="печатать каждую находку")
    ap.add_argument("--min-run", type=int, default=4,
                    help="минимальная длина хвоста (по умолчанию 4)")
    ap.add_argument("--pattern", default=DEFAULT_PATTERN,
                    help="regex флага (по умолчанию CTF{...}-подобный)")
    ap.add_argument("--fast", action="store_true",
                    help="не перебирать все маски инверсии строк (только чёт/нечет)")
    ap.add_argument("--trim", default="0,1,2,3",
                    help="сколько символов с конца хвостов отбрасывать (список)")
    args = ap.parse_args(argv)

    trims = tuple(int(x) for x in args.trim.split(",") if x.strip().isdigit())
    res = analyze(args.file, min_run=args.min_run, pattern=args.pattern,
                  verbose=args.verbose, full_masks=not args.fast,
                  trims=trims or (0,))
    if args.json:
        print(json.dumps(res, ensure_ascii=False, indent=2))
    else:
        print_human(res)
    return 0 if res["findings"] else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (FileNotFoundError, IsADirectoryError, PermissionError) as e:
        print("[-] не могу открыть: %s" % (getattr(e, "filename", None) or e))
        sys.exit(2)
    except BrokenPipeError:
        pass
    except KeyboardInterrupt:
        print("\n[-] прервано")
