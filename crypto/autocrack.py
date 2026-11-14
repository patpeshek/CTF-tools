#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
autocrack.py — «перебрать всё разумное» для крипты.

  python autocrack.py --text "Wkh txlfn..."
  python autocrack.py --hex 576b6820...
  python autocrack.py --file enc.bin
  python autocrack.py --text "..." --deep
  python autocrack.py --hash 5f4dcc3b5aa765d61d8327deb882cf99
  python autocrack.py --hash-file hashes.txt --wordlist auto

Что делает в auto-режиме:
  1) снимает кодировки (hex/base64/base32/url/binary/dec) рекурсивно;
  2) на каждом кандидате перебирает: Цезарь (26), Атбаш, аффинный (312),
     reverse, XOR (1 байт и повторяющийся ключ 2..12), rail fence (2..8),
     ROT47, Виженер (по качеству текста);
  3) ранжирует по печатности/частотности/наличию флага и печатает цепочку.

Хеши: определяет тип, ищет словарь (--wordlist или стандартные места),
поддерживает md5/sha1/sha256/sha512/ntlm, опционально простые мутации.
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
import base64
import binascii
import hashlib
import itertools
import os
import re
import sys
import time
import urllib.parse as up

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import classical as cl  # noqa: E402
import common  # noqa: E402

COMMON = ["the", "and", "flag", "ctf", "this", "that", "you", "with", "for",
          "are", "not", "have", "from", "was", "key", "secret", "message", "is"]
BUILTIN_WORDS = ["password", "123456", "12345678", "qwerty", "admin", "secret",
                 "letmein", "welcome", "monkey", "dragon", "master", "football",
                 "iloveyou", "sunshine", "princess", "login", "abc123", "111111",
                 "qwerty123", "1q2w3e4r", "passw0rd", "hello", "freedom", "whatever"]


def find_flag(s: str):
    flags = common.find_flags(s.encode("latin-1", "ignore"))
    return flags[0] if flags else None


def printable(s: str) -> float:
    if not s:
        return 0.0
    return sum(32 <= ord(c) < 127 or c in "\t\r\n" for c in s) / len(s)


def as_text(b: bytes):
    for enc in ("utf-8", "latin-1"):
        try:
            s = b.decode(enc)
        except UnicodeDecodeError:
            continue
        if printable(s) >= 0.9:
            return s
    return None


def score_text(s: str) -> float:
    if not s:
        return -1e9
    p = printable(s)
    if p < 0.85:
        return -1e6
    low = s.lower()
    cnt = {}
    n = 0
    for c in low:
        if "a" <= c <= "z":
            cnt[c] = cnt.get(c, 0) + 1
            n += 1
    sc = p * 10
    if n:
        chi = 0.0
        for c in "abcdefghijklmnopqrstuvwxyz":
            exp = cl.ENG_FREQ[c]
            obs = cnt.get(c, 0) / n * 100
            chi += (obs - exp) ** 2 / exp
        sc -= min(chi, 5000) / 50
    sc += sum(low.count(w) for w in COMMON) * 8
    if find_flag(s):
        sc += 1000
    if re.fullmatch(r"[A-Za-z0-9+/=]{20,}", s.strip()):
        sc -= 15
    return sc


def add_candidate(best, how, data):
    s = as_text(data)
    if not s:
        return
    sc = score_text(s)
    key = hashlib.md5(data).hexdigest()
    if key not in best or sc > best[key][0]:
        best[key] = (sc, how, s)


def decoders(data: bytes):
    """Простые кодировки: возвращает (название, bytes)."""
    out = []
    t = data.strip()
    if len(t) < 4 or len(t) > 200_000:
        return out
    try:
        s = t.decode("ascii")
    except UnicodeDecodeError:
        return out

    if re.fullmatch(r"[0-9a-fA-F\s:]+", s) and len(re.sub(r"\s:", "", s)) % 2 == 0:
        try:
            out.append(("hex → ", bytes.fromhex(re.sub(r"\s:|0x", "", s))))
        except ValueError:
            pass
    if re.fullmatch(r"[A-Za-z0-9+/=\s]+", s) and len(re.sub(r"\s", "", s)) >= 8:
        try:
            out.append(("base64 → ", base64.b64decode(re.sub(r"\s", "", s) + "=" * 4)))
        except Exception:
            pass
    if re.fullmatch(r"[A-Z2-7=\s]+", s.upper()) and len(re.sub(r"\s", "", s)) >= 8:
        try:
            out.append(("base32 → ", base64.b32decode(re.sub(r"\s", "", s.upper() + "===="))))
        except Exception:
            pass
    if "%" in s:
        out.append(("url → ", up.unquote(s).encode("latin-1", "replace")))
    if re.fullmatch(r"[01\s]{8,}", s):
        bits = re.sub(r"\s", "", s)
        out.append(("binary → ", bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits) - 7, 8))))
    if re.fullmatch(r"[\d\s,;]+", s):
        nums = [int(x) for x in re.findall(r"\d+", s)]
        if nums and all(0 <= n <= 0x10FFFF for n in nums):
            out.append(("dec → ", "".join(chr(n) for n in nums).encode("latin-1", "replace")))
    return out


def transform_bytes(b: bytes, how: str, best, deep=False):
    s = as_text(b)
    add_candidate(best, how + "(raw)", b)
    add_candidate(best, how + "reverse", b[::-1])

    # XOR не зависит от печатности — применяем всегда
    sample = b[:4096]
    for k in range(1, 256):
        add_candidate(best, f"{how}xor(0x{k:02x})", bytes(c ^ k for c in b))
    for klen in range(2, 13):
        key = bytearray()
        for i in range(klen):
            col = sample[i::klen]
            best_k, best_s = 0, -1
            for k in range(256):
                pts = sum(32 <= (c ^ k) < 127 or (c ^ k) in (9, 10, 13) for c in col)
                if pts > best_s:
                    best_s, best_k = pts, k
            key.append(best_k)
        dec = bytes(c ^ key[i % klen] for i, c in enumerate(b))
        add_candidate(best, f"{how}xor(key={bytes(key).hex()})", dec)

    if s is None:
        return

    # Цезарь / ROT13
    for k in range(1, 26):
        add_candidate(best, f"{how}caesar({k})", cl.caesar(s, k).encode("latin-1", "replace"))

    # Атбаш
    table = str.maketrans(cl.string.ascii_lowercase + cl.string.ascii_uppercase,
                          cl.string.ascii_lowercase[::-1] + cl.string.ascii_uppercase[::-1])
    add_candidate(best, how + "atbash", s.translate(table).encode("latin-1", "replace"))

    # аффинный
    for a in range(1, 26):
        if cl.math.gcd(a, 26) != 1:
            continue
        for bb in range(26):
            add_candidate(best, f"{how}affine({a},{bb})",
                          cl.affine_dec(s, a, bb).encode("latin-1", "replace"))

    # rail fence
    for rails in range(2, 9):
        dec = rail_fence_decrypt(s, rails)
        add_candidate(best, f"{how}rail({rails})", dec.encode("latin-1", "replace"))

    # ROT47 для печатного ASCII
    if printable(s) > 0.98:
        add_candidate(best, how + "rot47",
                      "".join(chr(33 + ((ord(c) - 33 + 47) % 94)) if 33 <= ord(c) <= 126 else c
                              for c in s).encode("latin-1", "replace"))

    # Виженер: только если текста достаточно и он буквенный
    letters = sum(c.isalpha() for c in s)
    if deep and len(s) >= 80 and letters / len(s) > 0.7:
        res = cl.vigenere_crack(s)
        if res:
            for sc, klen, key, plain in res[:2]:
                add_candidate(best, f"{how}vigenere({key})", plain.encode("latin-1", "replace"))


# невидимые символы, которыми прячут данные в обычном тексте
_ZW_RE = re.compile("[\u200b\u200c\u200d\u200e\u200f\u2060\u2061\u2062\u2063"
                    "\u180e\u00ad\ufeff]")


def zero_width_candidates(data: bytes):
    """zero-width → байты (base2 парами 200b/200c, base4 4 символа на байт).

    Реализация живёт в stego/whitespace.py (decode_zero_width); здесь только
    мост, чтобы «перебрать всё разумное» видело невидимые символы.
    """
    try:
        text = data.decode("utf-8", "replace")
    except Exception:
        return []
    if len(_ZW_RE.findall(text)) < 16:
        return []
    try:
        sys.path.insert(0, os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "stego"))
        import whitespace as wsmod  # noqa: E402
        return [(f"zero-width: {name}", dec)
                for name, dec in wsmod.decode_zero_width(text) if dec]
    except Exception:
        return []


def vigenere_phrase_candidates(raw: bytes, path, best):
    """Виженер с ключом-фразой из СОСЕДНЕГО текста (стих, письмо, цитата).

    В задачах ключ часто «спрятан» рядом: poem.txt, note.txt, lyrics.txt.
    Берём слова источника (окна по 2..6 слов, начала строк, акростих) и
    расшифровываем ими шифротекст; годный вариант ловится по score/флагу.
    """
    s = as_text(raw)
    if not s or not path or len(s) > 20000:
        return
    if sum(c.isalpha() for c in s) < 8:
        return
    d = os.path.dirname(os.path.abspath(path)) or "."
    me = os.path.abspath(path)
    try:
        names = sorted(os.listdir(d))[:400]
    except OSError:
        return
    sibs = []
    for nm in names:
        p2 = os.path.join(d, nm)
        if os.path.abspath(p2) == me or not os.path.isfile(p2):
            continue
        try:
            if os.path.getsize(p2) > 400_000:
                continue
            txt = open(p2, encoding="utf-8", errors="replace").read()
        except OSError:
            continue
        if printable(txt) < 0.9 or len(re.findall(r"[A-Za-z]", txt)) < 20:
            continue
        sibs.append((nm, txt))
    for nm, txt in sibs[:6]:
        for key in cl.phrase_keys(txt):
            add_candidate(best, f"vigenere(ключ {key} из {nm})",
                          cl.vigenere(s, key).encode("latin-1", "replace"))


def rail_fence_decrypt(s: str, rails: int) -> str:
    n = len(s)
    if rails <= 1 or rails >= n:
        return s
    pattern = list(range(rails)) + list(range(rails - 2, 0, -1))
    rail_seq = [pattern[i % len(pattern)] for i in range(n)]
    counts = [rail_seq.count(r) for r in range(rails)]
    rail_chars = []
    idx = 0
    for c in counts:
        rail_chars.append(list(s[idx:idx + c]))
        idx += c
    out = []
    ptr = [0] * rails
    for r in rail_seq:
        out.append(rail_chars[r][ptr[r]])
        ptr[r] += 1
    return "".join(out)


def auto_mode(args):
    if args.text is not None:
        raw = args.text.encode("utf-8", "replace")
    elif args.hex:
        raw = bytes.fromhex(re.sub(r"(?i)0x|[\s:]", "", args.hex))
    else:
        raw = open(args.file, "rb").read()

    if len(raw) > 200_000:
        print("[!] файл большой, беру первые 200 KB")
        raw = raw[:200_000]

    print(f"[+] вход: {len(raw)} b")
    best = {}
    frontier = [("", raw)]
    add_candidate(best, "(raw)", raw)

    depth = max(1, args.depth)
    for level in range(depth):
        nxt = []
        for how, data in frontier[:40]:
            for name, dec in decoders(data):
                chain = f"{how}{name}"
                add_candidate(best, chain, dec)
                nxt.append((chain, dec))
        frontier = nxt
        if not frontier:
            break

    # применяем преобразования к исходнику и ко всем раскодированным вариантам
    todo = [("", raw)] + [(h, d) for h, d in frontier]
    for how, data in todo[:60]:
        transform_bytes(data, how, best, deep=args.deep)

    # невидимые символы: 200b/200c/200d/feff как цифры (байт = 8 бит или 4 base4)
    for how, dec in zero_width_candidates(raw):
        add_candidate(best, how, dec)

    # Виженер, где ключ — фраза из соседнего текста (стих/письмо/цитата)
    if args.file:
        vigenere_phrase_candidates(raw, args.file, best)

    ranked = sorted(best.values(), key=lambda x: -x[0])
    shown = 0
    print(f"\n[+] кандидатов: {len(ranked)}")
    for sc, how, text in ranked:
        if sc < args.min_score:
            continue
        flag = find_flag(text)
        if not flag and not args.show_noise and printable(text) < 0.65:
            continue
        mark = "!!!" if flag else "   "
        print(f"\n{mark} score={sc:7.1f}  {how or '(raw)'}")
        print("    " + text[:300].replace("\n", "\\n"))
        if flag:
            print("    FLAG:", flag)
        shown += 1
        if shown >= args.top:
            break

    if not shown:
        print("[-] ничего убедительного. Дальше: dcode.fr, CyberChef, "
              "проверь ключ/пароль в соседних файлах, попробуй --deep и --min-score ниже.")


def hash_mode(args):
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import hash_id as hi  # noqa: E402

    if args.hash:
        hashes = [args.hash]
    else:
        hashes = [l.strip().split(":")[-1] for l in
                  open(args.hash_file, encoding="utf-8", errors="replace") if l.strip()]

    wordlist = []
    words_path = args.wordlist
    if words_path == "auto" or not words_path:
        for cand in ["./words.txt", "./rockyou.txt", "~/Downloads/rockyou.txt",
                     "/usr/share/wordlists/rockyou.txt",
                     "/usr/share/wordlists/rockyou.txt.gz",
                     r"C:\Tools\wordlists\rockyou.txt"]:
            p = os.path.expanduser(cand)
            if os.path.exists(p):
                words_path = p
                break
        else:
            words_path = None
    if words_path and words_path != "auto" and os.path.exists(words_path):
        opener = open
        if words_path.endswith(".gz"):
            import gzip
            opener = gzip.open
        wordlist = [l.strip() for l in opener(words_path, "rt", encoding="utf-8", errors="replace") if l.strip()]
        print(f"[+] словарь: {words_path} ({len(wordlist)})")
    else:
        wordlist = BUILTIN_WORDS
        print(f"[i] словарь не найден, использую встроенный ({len(wordlist)})")

    if args.rules:
        base = list(wordlist)
        for w in base[:20000]:
            wordlist += [w.lower(), w.upper(), w.capitalize(), w + "1", w + "123", w + "!"]

    algs = {
        "md5": hashlib.md5, "sha1": hashlib.sha1, "sha256": hashlib.sha256,
        "sha512": hashlib.sha512, "ntlm": None,
    }
    try:
        from Crypto.Hash import MD4
        algs["ntlm"] = lambda b: MD4.new(b.decode("utf-8", "replace").encode("utf-16le"))
    except Exception:
        pass

    for h in hashes:
        name, mode = hi.identify(h)
        print(f"\n[+] {h[:60]} -> {name}")
        target = h.lower()
        found = None
        t0 = time.time()
        for w in wordlist:
            for alg, fn in algs.items():
                if fn is None:
                    continue
                if fn(w.encode()).hexdigest() == target:
                    found = (alg, w)
                    break
            if found:
                break
        if found:
            print(f"[!!!] {found[0]}: {found[1]!r}  ({time.time()-t0:.2f}s)")
        else:
            print(f"[-] не найден за {time.time()-t0:.2f}s. "
                  f"Дальше: hashcat -m {mode.split()[0]} hash.txt {words_path or 'rockyou.txt'}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--text")
    ap.add_argument("--hex")
    ap.add_argument("--file")
    ap.add_argument("--hash")
    ap.add_argument("--hash-file")
    ap.add_argument("--wordlist", default="auto")
    ap.add_argument("--rules", action="store_true", help="простые мутации слов")
    ap.add_argument("--depth", type=int, default=2)
    ap.add_argument("--top", type=int, default=15)
    ap.add_argument("--min-score", type=float, default=1.0)
    ap.add_argument("--show-noise", action="store_true", help="показывать мусорные кандидаты")
    ap.add_argument("--deep", action="store_true", help="тяжёлые проверки (Виженер)")
    common.add_flag_args(ap)
    args = ap.parse_args()
    common.apply_flag_args(args)

    if args.hash or args.hash_file:
        hash_mode(args)
        return
    if not (args.text or args.hex or args.file):
        ap.error("нужен --text, --hex, --file или --hash")
    auto_mode(args)


if __name__ == "__main__":
    main()
