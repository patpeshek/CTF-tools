"""eval_true.py — честный замер на настоящих файлах с автоматическим ключом.

В отличие от `eval_real.py` (там ключ рукописный и только для 19 учебных
задач), здесь ключ выводится детерминированно из самих байтов: сигнатуры
контейнеров и простые текстовые эвристики. Это не идеальная разметка, но она
воспроизводима и позволяет мерить модель на любом наборе файлов.

Файлы, для которых семейство не определяется однозначно, помечаются `-` и не
попадают в точность.

  python ml/eval_true.py --model F:\\AIproject\\ml-runs\\mlp_v5.pt ^
      --dir F:\\AIproject\\ctf-files\\таски
"""
from __future__ import annotations

import argparse
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import numpy as np

# сигнатуры в порядке приоритета: (смещение, байты, семейство)
SIGS = [
    (0, b"\x89PNG\r\n\x1a\n", "png"),
    (0, b"\xff\xd8\xff", "jpeg"),
    (0, b"GIF8", "gif"),
    (0, b"PK\x03\x04", "zip"),
    (0, b"PK\x05\x06", "zip"),
    (0, b"\x1f\x8b", "gzip"),
    (0, b"\xfd7zXZ\x00", "xz"),
    (0, b"BZh", "bz2"),
    (0, b"%PDF", "pdf"),
    (0, b"\x7fELF", "elf"),
    (0, b"MZ", "pe"),
    (0, b"SQLite format 3\x00", "sqlite"),
    (0, b"\xd4\xc3\xb2\xa1", "pcap"),
    (0, b"\xa1\xb2\xc3\xd4", "pcap"),
    (0, b"\x0a\x0d\x0d\x0a", "pcapng"),
    (0, b"ID3", "mp3"),
    (0, b"\xff\xfb", "mp3"),
    (0, b"\xff\xf3", "mp3"),
    (0, b"RIFF", "wav"),
    (0, b"OggS", "ogg"),
    (0, b"fLaC", "flac"),
    (0, b"{\\rtf", "rtf"),
]

TS_RE = re.compile(rb"\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}")
ISO_RE = re.compile(rb"\b20\d\d-\d\d-\d\d[tT ]\d\d:\d\d")
# «это исходный код»: питон, C/C++, Go, JS/TS, Ruby, PHP, Java, шелл.
# Раньше здесь были только питон и C, поэтому .js и .rb уходили в конфиги/логи.
CODE_RE = re.compile(
    rb"(?m)^\s*(?:def |class |import |from \w+ import |#include|public |static "
    rb"|func |const |let |var |function |async |await |module\.exports|require\("
    rb"|export (?:default|const|function)|package main|interface |namespace "
    rb"|using \w+|#!|use strict|my \$|sub \w+|\$this->|public function "
    rb"|elsif |begin$|end$)")
CODE_EXT = {".py", ".js", ".ts", ".jsx", ".tsx", ".rb", ".php", ".java", ".go",
            ".rs", ".c", ".cc", ".cpp", ".h", ".hpp", ".cs", ".sh", ".pl",
            ".lua", ".kt", ".swift", ".scala", ".m", ".r", ".jl", ".ex", ".exs"}
CONF_RE = re.compile(rb"(?m)^\s*(?:version:|services:|\[server\]|\[auth\]|FROM |ENV |RUN )")


def expected(data: bytes, path: str = "") -> str:
    """Семейство по содержимому; '-' если однозначно не сказать."""
    ext = os.path.splitext(path)[1].lower() if path else ""
    if ext in CODE_EXT and not data.startswith((b"\x7fELF", b"MZ", b"PK")):
        return "py_src"
    for off, sig, fam in SIGS:
        if data[off:off + len(sig)] == sig:
            if fam == "wav" and data[8:12] != b"WAVE":
                continue
            return fam
    if len(data) >= 512 and data[510:512] == b"\x55\xaa":
        return "disk_img"
    sample = data[:65536]
    printable = sum(1 for b in sample if 32 <= b < 127 or b in (9, 10, 13)) / max(1, len(sample))
    if printable < 0.9:
        return "-"
    text = sample.lstrip()
    lines = [ln for ln in sample.splitlines() if ln.strip()]
    if lines and sum(1 for ln in lines[:50] if ln.lstrip().startswith(b"{")) > len(lines[:50]) * 0.8:
        return "json_log"
    if CODE_RE.search(sample):
        return "py_src"
    if sample.lstrip().startswith(b"#!"):
        return "py_src"
    if CONF_RE.search(sample):
        return "config_text"
    if TS_RE.search(sample) or ISO_RE.search(sample):
        return "plain_log"
    return "-"


def iter_files(root):
    for dirpath, _dirs, names in os.walk(root):
        for n in sorted(names):
            p = os.path.join(dirpath, n)
            try:
                if os.path.getsize(p) > 0:
                    yield p
            except OSError:
                continue


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True)
    ap.add_argument("--dir", required=True)
    ap.add_argument("--top", type=int, default=3)
    ap.add_argument("--threshold", type=float, default=0.5)
    ap.add_argument("--show", type=int, default=0, help="показать N строк (0 — все)")
    args = ap.parse_args()

    from eval_dir import load
    kind, predict, families = load(args.model)
    print(f"[+] модель: {kind}, классов: {len(families)}", flush=True)

    rows, tally = [], {}
    for p in iter_files(args.dir):
        data = open(p, "rb").read()
        exp = expected(data, p)
        probs = predict(data)
        idx = np.argsort(-probs)[:args.top]
        got = families[idx[0]]
        top = " | ".join(f"{families[i]} {probs[i]:.2f}" for i in idx)
        ok = "-" if exp == "-" or exp not in families else ("OK" if got == exp else "WRONG")
        rows.append((ok, exp, got, os.path.relpath(p, args.dir), len(data), top,
                     float(probs[idx[0]])))
        if exp not in ("-",) and exp in families:
            tally.setdefault(exp, [0, 0])
            tally[exp][0] += got == exp
            tally[exp][1] += 1

    limit = args.show or len(rows)
    for ok, exp, got, rel, size, top, best in rows[:limit]:
        mark = {"OK": "OK   ", "WRONG": "WRONG", "-": "  -  "}[ok]
        unsure = "  [не уверен]" if best < args.threshold else ""
        print(f"  {mark} {rel:56s} {size:>9d}B  exp={exp:11s} {top}{unsure}", flush=True)

    total_ok = sum(v[0] for v in tally.values())
    total_n = sum(v[1] for v in tally.values())
    print(flush=True)
    print(f"[=] точность по распознанным: {total_ok}/{total_n} = {total_ok / max(1, total_n):.1%}", flush=True)
    print("[=] по семействам:", flush=True)
    for fam, (ok, n) in sorted(tally.items(), key=lambda kv: (kv[1][0] / kv[1][1], -kv[1][1])):
        print(f"    {fam:12s} {ok}/{n}", flush=True)
    wrong = {}
    for ok, exp, got, _rel, _s, _t, _b in rows:
        if ok == "WRONG":
            wrong[(exp, got)] = wrong.get((exp, got), 0) + 1
    if wrong:
        print("[=] путаница: " + ", ".join(f"{a}→{b}×{n}" for (a, b), n in
                                           sorted(wrong.items(), key=lambda kv: -kv[1])[:12]),
              flush=True)


if __name__ == "__main__":
    main()
