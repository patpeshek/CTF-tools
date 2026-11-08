#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
megaall.py — «запусти и дай что есть». Универсальный перебор.

  python megaall.py --dir dump
  python megaall.py --file enc.bin --file note.txt
  python megaall.py --hex 4a3f... --text "seed=..."
  python megaall.py --dir dump --deep --top 30

Что делает:
  1) собирает артефакты: файлы, папки, zip-внутренности, строки, hex/base64-блоки,
     JSON-скаляры, имена файлов, большие числа;
  2) ищет готовые флаги и хеши;
  3) выбирает кандидатов в шифротекст (бинарные файлы, длинные hex/base64);
  4) на каждом: снимает кодировки, гоняет autocrack (Цезарь/аффинный/XOR/rail/…);
  5) собирает ключи из материалов и гоняет megacrack (XOR/RC4/AES/поток/Виженер);
  6) пробует RSA: общий множитель, Ферма, малая экспонента;
  7) ранжирует результаты и печатает цепочку + флаги.

Без аргументов сканирует текущую папку (осторожно: может быть долго).
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
import hashlib
import json
import math
import os
import re
import sys
import time
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
for sub in ("crypto", "forensic", "network", "stego"):
    sys.path.insert(0, os.path.join(HERE, sub))
sys.path.insert(0, HERE)

import common          # noqa: E402
import autocrack as ac  # noqa: E402
import megacrack as mg  # noqa: E402
import hash_id as hi    # noqa: E402

try:
    import whitespace as wsmod  # noqa: E402
    import esolang as esomod    # noqa: E402
except Exception:  # pragma: no cover
    wsmod = esomod = None

MAX_FILE = 2_000_000
MAX_BLOB = 200_000
MAX_BLOBS = 12
MAX_TOKENS = 60
MAX_PAIRS = 12

HASH_RE = re.compile(r"\b(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64}|[a-f0-9]{128})\b")
BIGINT_RE = re.compile(r"\b(?:0x[0-9a-fA-F]{40,}|\d{50,})\b")
HEX_RUN = re.compile(r"\b[0-9a-fA-F]{16,}\b")
B64_RUN = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")


def is_binary(data: bytes) -> bool:
    if not data:
        return False
    sample = data[:4096]
    nontext = sum(c < 9 or 13 < c < 32 or c > 126 for c in sample)
    return nontext / len(sample) > 0.2


class Bag:
    def __init__(self):
        self.tokens = {}
        self.blobs = []       # (label, bytes)
        self.hashes = {}
        self.bigints = []     # (label, int)
        self.flags = set()

    def add_blob(self, label, data):
        if not data or len(data) < 6:
            return
        if len(data) > MAX_BLOB:
            data = data[:MAX_BLOB]
        key = hashlib.md5(data).hexdigest()
        if any(hashlib.md5(b).hexdigest() == key for _, b in self.blobs):
            return
        if len(self.blobs) < MAX_BLOBS:
            self.blobs.append((label, data))

    def add_text(self, text, label):
        mg.tokens_from_text(text, self.tokens, prefix=f"{label}:")
        for f in common.find_flags(text.encode("utf-8", "replace")):
            self.flags.add(f)
        for h in HASH_RE.findall(text):
            self.hashes[h] = label
        for m in BIGINT_RE.finditer(text):
            try:
                v = int(m.group(), 0)
                if v.bit_length() > 128:
                    self.bigints.append((label, v))
            except ValueError:
                pass
        # именованные числа RSA в тексте/JSON: n/e/c/p/q/d
        for m in re.finditer(r'"(n|e|d|p|q|c|cipher|modulus)"\s*:\s*"?([0-9a-fA-Fx]+)"?',
                             text, re.I):
            try:
                self.bigints.append((m.group(1).lower(), int(m.group(2), 0)))
            except ValueError:
                pass
        for line in text.splitlines():
            kv = mg.KV.match(line.strip())
            if kv and re.fullmatch(r"(?i)(n|e|d|p|q|c|cipher|modulus)", kv.group(1)):
                try:
                    self.bigints.append((kv.group(1).lower(), int(kv.group(2).strip(), 0)))
                except ValueError:
                    pass
        for h in HEX_RUN.findall(text):
            try:
                self.add_blob(f"{label}:hex", bytes.fromhex(h))
            except ValueError:
                pass
        for b in B64_RUN.findall(text):
            for how, dec in common.decode_field(b):
                if how == "base64" and dec:
                    self.add_blob(f"{label}:b64", dec)
        self.weird(text, label)

    def weird(self, text, label):
        if not wsmod or len(text) > 20000:
            return
        try:
            if text and all(c in " \t\r\n" for c in text):
                out, _ = wsmod.run_ws(text)
                if out:
                    self.flags.update(common.find_flags(out.encode("utf-8", "replace")))
                    self.add_blob(f"{label}:ws", out.encode("utf-8", "replace"))
            if any(0x200b <= ord(c) <= 0x200d or 0x2060 <= ord(c) <= 0x2060 or
                   ord(c) == 0xfeff for c in text):
                for name, dec in wsmod.decode_zero_width(text):
                    self.add_blob(f"{label}:{name}", dec)
                    self.flags.update(common.find_flags(dec))
            if any(0x2800 <= ord(c) <= 0x28ff for c in text):
                for name, dec in wsmod.decode_braille(text):
                    self.add_blob(f"{label}:{name}", dec)
                    self.flags.update(common.find_flags(dec))
            if any(0xFE00 <= ord(c) <= 0xFE0F for c in text):
                for name, dec in wsmod.decode_variation(text):
                    self.add_blob(f"{label}:{name}", dec)
            if esomod:
                lang = esomod.detect(text)
                if lang in ("bf", "ook", "cow", "befunge", "deadfish"):
                    if lang == "bf":
                        out, _ = esomod.run_bf(text)
                    elif lang == "ook":
                        out, _ = esomod.run_bf(esomod.ook_to_bf(text))
                    elif lang == "cow":
                        out, _ = esomod.run_bf(esomod.cow_to_bf(text))
                    elif lang == "befunge":
                        out, _ = esomod.run_befunge(text)
                    else:
                        out, _ = esomod.run_deadfish(text)
                    if out:
                        self.flags.update(common.find_flags(out.encode("utf-8", "replace")))
                        self.add_blob(f"{label}:{lang}", out.encode("utf-8", "replace"))
        except Exception:
            pass

    def add_bytes(self, data, label):
        for f in common.find_flags(data):
            self.flags.add(f)
        if is_binary(data):
            self.add_blob(label, data)
            for _, s in common.strings(data, 6, 100):
                mg.add_token(self.tokens, s, f"{label}:str")
        else:
            self.add_text(data.decode("utf-8", "replace"), label)


def scan_path(path, bag, depth=0):
    if depth > 1:
        return
    if os.path.isdir(path):
        try:
            files = sorted(os.listdir(path))[:200]
        except OSError:
            return
        for f in files:
            scan_path(os.path.join(path, f), bag, depth + 1)
        return
    try:
        if os.path.getsize(path) > MAX_FILE * 2:
            return
        data = open(path, "rb").read(MAX_FILE)
    except OSError:
        return
    label = os.path.basename(path)
    mg.add_token(bag.tokens, os.path.splitext(label)[0], "filename:")
    if zipfile.is_zipfile(path):
        try:
            with zipfile.ZipFile(path) as z:
                for info in z.infolist()[:50]:
                    if info.file_size > MAX_FILE:
                        continue
                    entry = z.read(info)
                    bag.add_bytes(entry, f"{label}!{info.filename}")
        except Exception:
            bag.add_bytes(data, label)
    else:
        bag.add_bytes(data, label)


def crack_hashes(hashes, wordlist, rules, limit=50000):
    words = []
    path = wordlist
    if path in (None, "auto"):
        for cand in ("./words.txt", "./rockyou.txt", "~/Downloads/rockyou.txt",
                     "/usr/share/wordlists/rockyou.txt"):
            p = os.path.expanduser(cand)
            if os.path.exists(p):
                path = p
                break
    if path and path != "auto" and os.path.exists(path):
        try:
            words = [l.strip() for l in open(path, encoding="utf-8", errors="replace") if l.strip()]
        except OSError:
            words = []
    if not words:
        words = ac.BUILTIN_WORDS
    words = words[:limit]
    if rules:
        base = list(words[:5000])
        for w in base:
            words += [w.lower(), w.upper(), w.capitalize(), w + "1", w + "123", w + "!"]

    algs = {"md5": hashlib.md5, "sha1": hashlib.sha1,
            "sha256": hashlib.sha256, "sha512": hashlib.sha512}
    found = []
    for h in hashes:
        target = h.lower()
        for alg, fn in algs.items():
            for w in words:
                if fn(w.encode()).hexdigest() == target:
                    found.append((h, alg, w))
                    break
            else:
                continue
            break
    return found


def textify(m):
    b = m.to_bytes((m.bit_length() + 7) // 8, "big") if m else b"\x00"
    s = ac.as_text(b)
    return s if s else f"int={m} hex={b.hex()}"


def try_rsa(bag):
    results = []
    ints = bag.bigints
    if not ints:
        return results
    ns = [(l, v) for l, v in ints if l in ("n", "modulus") or v.bit_length() >= 256]
    if not ns:
        ns = sorted(ints, key=lambda x: -x[1].bit_length())[:3]
    cs = [(l, v) for l, v in ints if l in ("c", "cipher")]
    if not cs:
        cs = [(l, v) for l, v in ints if v not in [n for _, n in ns]]

    # общий множитель
    for i in range(len(ns)):
        for j in range(i + 1, len(ns)):
            n1, n2 = ns[i][1], ns[j][1]
            g = math.gcd(n1, n2)
            if 1 < g < min(n1, n2):
                n = n1 if n1 % g == 0 else n2
                p, q = g, n // g
                for label, c in cs:
                    if c < n and c > 1:
                        for e in (65537, 3, 17):
                            try:
                                d = pow(e, -1, (p - 1) * (q - 1))
                            except ValueError:
                                continue
                            m = pow(c, d, n)
                            results.append((f"RSA shared p ({label})", textify(m)))
    # Ферма для чисел без общего множителя
    from math import isqrt
    for label, n in ns[:3]:
        a = isqrt(n)
        if a * a < n:
            a += 1
        for _ in range(200000):
            b2 = a * a - n
            b = isqrt(b2)
            if b * b == b2:
                p, q = a - b, a + b
                for l2, c in cs:
                    if c < n and c > 1:
                        try:
                            d = pow(65537, -1, (p - 1) * (q - 1))
                            m = pow(c, d, n)
                            results.append((f"RSA Fermat ({l2})", textify(m)))
                        except Exception:
                            pass
                break
            a += 1
    # малая экспонента
    for label, n in ns:
        for e in (3, 17, 65537):
            for l2, c in cs:
                if c >= n:
                    continue
                lo, high = 0, 1 << ((n.bit_length() // e) + 2)
                while lo < high:
                    mid = (lo + high) // 2
                    if mid ** e < c:
                        lo = mid + 1
                    else:
                        high = mid
                if lo ** e == c:
                    results.append((f"RSA small-e={e} ({l2})", textify(lo)))
    return results


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--file", action="append", default=[])
    ap.add_argument("--dir", action="append", default=[])
    ap.add_argument("targets", nargs="*", help="файлы/папки можно указывать просто позицией")
    ap.add_argument("--text")
    ap.add_argument("--hex")
    ap.add_argument("--top", type=int, default=20)
    ap.add_argument("--min-score", type=float, default=1.0)
    ap.add_argument("--show-noise", action="store_true")
    ap.add_argument("--deep", action="store_true")
    ap.add_argument("--time", type=int, default=90, help="лимит секунд на перебор")
    ap.add_argument("--wordlist", default="auto")
    ap.add_argument("--rules", action="store_true")
    ap.add_argument("--no-hash", action="store_true")
    ap.add_argument("--no-rsa", action="store_true")
    ap.add_argument("--json", action="store_true")
    common.add_flag_args(ap)
    args = ap.parse_args()
    common.apply_flag_args(args)
    args.file = list(args.file) + list(args.targets)

    if not (args.file or args.dir or args.text or args.hex):
        args.dir = ["."]
        print("[i] ничего не дано — сканирую текущую папку")

    bag = Bag()
    for p in args.file:
        scan_path(p, bag)
    for d in args.dir:
        scan_path(d, bag)
    if args.text:
        bag.add_text(args.text, "cli")
        bag.add_blob("cli-text", args.text.encode("latin-1", "replace"))
    if args.hex:
        data = bytes.fromhex(re.sub(r"(?i)0x|[\s:]", "", args.hex))
        bag.add_bytes(data, "cli-hex")
        bag.add_blob("cli-hex", data)

    print(f"[+] токенов: {len(bag.tokens)}  блобов: {len(bag.blobs)}  "
          f"хешей: {len(bag.hashes)}  чисел: {len(bag.bigints)}  флагов: {len(bag.flags)}")

    start = time.time()
    deadline = start + args.time
    best = {}
    keys = mg.key_candidates(bag.tokens, MAX_TOKENS, MAX_PAIRS) if bag.tokens else {}
    print(f"[+] кандидатов в ключи: {len(keys)}")

    for label, data in bag.blobs:
        if time.time() > deadline:
            print("[!] лимит времени на перебор")
            break
        # кодировки
        ac.add_candidate(best, f"[{label}] raw", data)
        # known-plaintext: открытый текст начинается с префикса флага
        for pre, xkey, plain in common.xor_prefix_hits(data):
            ac.add_candidate(best, f"[{label}] xor-known({pre},k={len(xkey)})", plain)
        frontier = [("", data)]
        for _ in range(2):
            nxt = []
            for how, d in frontier[:20]:
                for name, dec in ac.decoders(d):
                    ac.add_candidate(best, f"[{label}] {how}{name}", dec)
                    nxt.append((how + name, dec))
            frontier = nxt

        # без ключа
        for how, d in [("", data)] + frontier[:10]:
            ac.transform_bytes(d, f"[{label}] {how}", best, deep=args.deep)

        # с ключами
        if keys:
            for key, klabel in list(keys.items())[:300]:
                if time.time() > deadline:
                    break
                mg.try_key(data, f"[{label}] {klabel}", key, best, deep=args.deep)

    # хеши
    hash_found = []
    if bag.hashes and not args.no_hash:
        print(f"[+] пробую хеши ({len(bag.hashes)})...")
        hash_found = crack_hashes(list(bag.hashes), args.wordlist, args.rules)

    # RSA
    rsa_found = [] if args.no_rsa else try_rsa(bag)

    ranked = sorted(best.values(), key=lambda x: -x[0])
    flags = set(bag.flags)
    for sc, how, text in ranked:
        f = ac.find_flag(text)
        if f:
            flags.add(f)

    if args.json:
        print(json.dumps({
            "flags": sorted(flags),
            "hashes": [{"hash": h, "alg": a, "word": w} for h, a, w in hash_found],
            "rsa": [{"how": h, "text": t} for h, t in rsa_found],
            "candidates": [{"score": sc, "how": how, "text": t[:500]}
                           for sc, how, t in ranked[:args.top]],
        }, ensure_ascii=False, indent=2))
        return

    if flags:
        print("\n=== ФЛАГИ ===")
        for f in sorted(flags):
            print(" !!!", f)
    if hash_found:
        print("\n=== ХЕШИ ===")
        for h, a, w in hash_found:
            print(f" {h[:60]} -> {a}: {w!r}")
    if rsa_found:
        print("\n=== RSA ===")
        for how, text in rsa_found:
            print(f" {how}: {text[:200]}")

    print(f"\n=== КАНДИДАТЫ (за {time.time()-start:.1f}s) ===")
    shown = 0
    for sc, how, text in ranked:
        if sc < args.min_score:
            continue
        flag = ac.find_flag(text)
        if not flag and not args.show_noise and common.printable_ratio(text.encode("utf-8", "replace")) < 0.65:
            continue
        mark = "!!!" if flag else "   "
        print(f"\n{mark} score={sc:7.1f}  {how}")
        print("    " + text[:260].replace("\n", "\\n"))
        shown += 1
        if shown >= args.top:
            break
    if not shown:
        print("[-] ничего. Добавь материалы/файлы, включи --deep или проверь формат флага.")


if __name__ == "__main__":
    main()
