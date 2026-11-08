#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
genetic.py — триплеты РНК/ДНК → аминокислоты.

  python genetic.py "UGUACUUUC{GGGGAGAACGAGACAAUCUGU_AUGGAGUCGAGUGCAGGAGAG}"
  python genetic.py --file task.txt
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
import re

CODONS = {
    'UUU': 'F', 'UUC': 'F', 'UUA': 'L', 'UUG': 'L',
    'CUU': 'L', 'CUC': 'L', 'CUA': 'L', 'CUG': 'L',
    'AUU': 'I', 'AUC': 'I', 'AUA': 'I', 'AUG': 'M',
    'GUU': 'V', 'GUC': 'V', 'GUA': 'V', 'GUG': 'V',
    'UCU': 'S', 'UCC': 'S', 'UCA': 'S', 'UCG': 'S',
    'CCU': 'P', 'CCC': 'P', 'CCA': 'P', 'CCG': 'P',
    'ACU': 'T', 'ACC': 'T', 'ACA': 'T', 'ACG': 'T',
    'GCU': 'A', 'GCC': 'A', 'GCA': 'A', 'GCG': 'A',
    'UAU': 'Y', 'UAC': 'Y', 'UAA': '*', 'UAG': '*',
    'CAU': 'H', 'CAC': 'H', 'CAA': 'Q', 'CAG': 'Q',
    'AAU': 'N', 'AAC': 'N', 'AAA': 'K', 'AAG': 'K',
    'GAU': 'D', 'GAC': 'D', 'GAA': 'E', 'GAG': 'E',
    'UGU': 'C', 'UGC': 'C', 'UGA': '*', 'UGG': 'W',
    'CGU': 'R', 'CGC': 'R', 'CGA': 'R', 'CGG': 'R',
    'AGU': 'S', 'AGC': 'S', 'AGA': 'R', 'AGG': 'R',
    'GGU': 'G', 'GGC': 'G', 'GGA': 'G', 'GGG': 'G',
}


def decode(text: str, stop_at_stop=False) -> str:
    text = text.upper().replace('T', 'U')
    out, buf = [], ''
    for ch in text:
        if ch in 'ACGU':
            buf += ch
            if len(buf) == 3:
                aa = CODONS.get(buf, '?')
                if aa == '*' and stop_at_stop:
                    return ''.join(out)
                out.append(aa)
                buf = ''
        else:
            if buf:
                out.append('?')
                buf = ''
            out.append(ch)
    return ''.join(out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("text", nargs="?")
    ap.add_argument("--file")
    ap.add_argument("--stop-at-stop", action="store_true", help="обрывать на стоп-кодоне")
    args = ap.parse_args()
    text = args.text
    if args.file:
        text = open(args.file, encoding="utf-8", errors="replace").read()
    if not text:
        ap.error("нужен текст или --file")
    print(decode(text, args.stop_at_stop))


if __name__ == "__main__":
    main()
