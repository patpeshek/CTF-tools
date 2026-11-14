#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
classical.py — классические шифры: Цезарь, аффинный, Виженер, Атбаш, морзе,
multitap (кнопочный телефон), Плейфер.

  python classical.py caesar --text "Wkh txlfn"            # брут всех сдвигов
  python classical.py caesar --text "Wkh txlfn" --key 3
  python classical.py affine --text "..." --known "AGENT"  # найти a,b по префиксу
  python classical.py affine --text "..." --a 5 --b 8
  python classical.py vigenere --text "..." --key LEMON
  python classical.py vigenere --text "..." --key LEMON --encrypt
  python classical.py atbash --text "..."
  python classical.py morse --text ".... . .-.. .-.. ---"
  python classical.py multitap --text "222 33 555 666"
  python classical.py playfair --text "..." --key MONARCHY
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
import collections
import itertools
import math
import os
import random
import re
import string
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import common  # noqa: E402

ENG_FREQ = {
    'a': 8.17, 'b': 1.49, 'c': 2.78, 'd': 4.25, 'e': 12.70, 'f': 2.23, 'g': 2.02,
    'h': 6.09, 'i': 6.97, 'j': 0.15, 'k': 0.77, 'l': 4.03, 'm': 2.41, 'n': 6.75,
    'o': 7.51, 'p': 1.93, 'q': 0.10, 'r': 5.99, 's': 6.33, 't': 9.06, 'u': 2.76,
    'v': 0.98, 'w': 2.36, 'x': 0.15, 'y': 1.97, 'z': 0.07,
}
COMMON = ["the", "and", "flag", "ctf", "this", "that", "you", "with", "for", "are",
          "not", "have", "from", "was", "key", "secret", "message"]


def score_text(s: str) -> float:
    low = s.lower()
    letters = [c for c in low if c in string.ascii_lowercase]
    if not letters:
        return -1e9
    n = len(letters)
    chi = 0.0
    for c in string.ascii_lowercase:
        observed = letters.count(c) / n * 100
        expected = ENG_FREQ[c]
        chi += (observed - expected) ** 2 / expected
    words = sum(low.count(w) for w in COMMON)
    ic = index_of_coincidence(low)
    return -chi + words * 30 + ic * 200


def caesar(text: str, shift: int) -> str:
    out = []
    for c in text:
        if 'a' <= c <= 'z':
            out.append(chr((ord(c) - 97 - shift) % 26 + 97))
        elif 'A' <= c <= 'Z':
            out.append(chr((ord(c) - 65 - shift) % 26 + 65))
        else:
            out.append(c)
    return ''.join(out)


def affine_dec(text: str, a: int, b: int) -> str:
    inv = pow(a, -1, 26)
    out = []
    for c in text:
        if c.isalpha():
            base = 65 if c.isupper() else 97
            x = ord(c) - base
            out.append(chr((inv * (x - b)) % 26 + base))
        else:
            out.append(c)
    return ''.join(out)


def vigenere(text: str, key: str, encrypt=False) -> str:
    key = [ord(c.lower()) - 97 for c in key if c.isalpha()]
    if not key:
        return text
    out, j = [], 0
    for c in text:
        if c.isalpha():
            base = 65 if c.isupper() else 97
            k = key[j % len(key)]
            shift = k if encrypt else -k
            out.append(chr((ord(c) - base + shift) % 26 + base))
            j += 1
        else:
            out.append(c)
    return ''.join(out)


def vigenere_alpha(text: str, key: str, alphabet: str, encrypt=False) -> str:
    """Виженер по произвольному алфавиту (буквы+цифры+`_` и т.п.)."""
    key = [c.lower() for c in key if c.lower() in alphabet]
    if not key or len(alphabet) < 2:
        return text
    out, j = [], 0
    for c in text:
        low = c.lower()
        if low in alphabet:
            idx = alphabet.index(low)
            k = alphabet.index(key[j % len(key)])
            idx = (idx + k) % len(alphabet) if encrypt else (idx - k) % len(alphabet)
            ch = alphabet[idx]
            out.append(ch.upper() if c.isupper() else ch)
            j += 1
        else:
            out.append(c)
    return "".join(out)


ALPHABET_VARIANTS = [
    "abcdefghijklmnopqrstuvwxyz",
    "abcdefghijklmnopqrstuvwxyz0123456789",
    "abcdefghijklmnopqrstuvwxyz0123456789_",
    "abcdefghijklmnopqrstuvwxyz_0123456789",
    "0123456789abcdefghijklmnopqrstuvwxyz_",
    "abcdefghijklmnopqrstuvwxyz_",
]


def _dict_score(plain: str, vocab: set) -> float:
    """Словарные попадания + частотный скор + бонус за флаг внутри текста."""
    toks = [t for t in re.split(r"[^a-z0-9]+", plain.lower()) if t]
    if not toks:
        return -1e9
    hits = sum(1 for t in toks if t in vocab or t.rstrip("0123456789") in vocab)
    # english_score любит короткие строки с повторами (IC), поэтому вес умеренный
    sc = hits * 10 + english_score(plain) * 0.4
    # флаг в тексте — сильный сигнал, но только если текст размечен словами
    # (иначе `zhnto{...}` из случайного ключа получает бонус незаслуженно)
    if any(sep in plain for sep in ("_", "-", " ")):
        try:
            if common.find_flags(plain.encode("utf-8", "replace")):
                sc += 30
        except Exception:
            pass
    return sc


def alphabet_candidates(text: str):
    """Алфавиты-кандидаты для шифротекста: буквы + цифры + то, что реально есть.

    Генератор задачи мог взять `a-z0-9`, `a-z0-9_`, `a-z0-9_{}` или что-то
    своё. Порядок внутри алфавита важен (от него зависит сдвиг), поэтому
    пробуем несколько типовых раскладок пунктуации.
    """
    letters = "abcdefghijklmnopqrstuvwxyz"
    digits = "0123456789"
    punct = []
    for c in text.lower():
        if not c.isalnum() and c not in " \t\r\n" and c not in punct:
            punct.append(c)
    orders = ["", "_", "{}", "_{}", "{}_", "_-{}", "{}_-", "_-", "-_"]
    out = []
    for base in (letters + digits, letters, digits + letters):
        for order in orders:
            extra = order + "".join(c for c in punct if c not in order)
            alpha = base + extra
            if alpha in out:
                continue
            if set(text.lower()) <= set(alpha) | set(" \t\r\n"):
                out.append(alpha)
    return out


def phrase_keys(text: str, max_words: int = 6, limit: int = 2000):
    """Кандидаты в ключ Виженера из связного текста: стих, письмо, цитата.

    Ключ-фразу в задачах берут словами из условия: «первые три слова второй
    строки», «вся строка без пробелов», «акростих». Поэтому из каждой строки
    источника собираем все окна по 2..max_words слов, начала/хвосты строк,
    акростих и строку целиком.
    """
    keys, seen = [], set()

    def push(words):
        k = "".join(words).lower()
        if 2 <= len(k) <= 60 and k.isalpha() and k not in seen:
            seen.add(k)
            keys.append(k)

    for line in [ln for ln in text.splitlines() if ln.strip()][:60]:
        words = re.findall(r"[A-Za-z]+", line)
        if len(words) < 2:
            continue
        n_max = min(max_words, len(words))
        for n in range(2, n_max + 1):
            push(words[:n])                 # первые n слов строки
            push(words[-n:])                # последние n слов
            for i in range(len(words) - n + 1):
                push(words[i:i + n])        # любое окно из n слов подряд
        push([w[0] for w in words])         # акростих
        if len(words) > n_max:
            push(words)                     # вся строка без пробелов
    return keys[:limit]


def vigenere_phrase_crack(text: str, source: str, top: int = 8):
    """Виженер, где ключ — фраза из источника; результат по качеству текста."""
    res = []
    for key in phrase_keys(source):
        plain = vigenere(text, key)
        sc = score_text(plain)
        try:
            if common.find_flags(plain.encode("utf-8", "replace")):
                sc += 500
        except Exception:
            pass
        res.append((sc, key, plain))
    res.sort(key=lambda x: -x[0])
    return res[:top]


def vigdict_crack(text: str, words: list[str], alphabets=None, need=None,
                  top: int = 10):
    """Словарная атака на Виженера: каждое слово словаря — кандидат в ключ.

    Для шифротекста со цифрами/`_` перебираются несколько алфавитов: генератор
    задачи часто берёт `a-z0-9_`, а не чистые буквы — поэтому обычный
    vigenere-crack на таком тексте бесполезен.
    """
    vacab = {w.lower() for w in words if w}
    words = [w for w in dict.fromkeys(w.lower() for w in words if w)]
    if alphabets is None:
        alphabets = alphabet_candidates(text) or ["abcdefghijklmnopqrstuvwxyz"]
    need_low = [n.lower() for n in (need or [])]
    res = []
    for alpha in alphabets:
        alpha_words = [w for w in words if all(c in alpha for c in w)]
        for key in alpha_words:
            plain = vigenere_alpha(text, key, alpha)
            low = plain.lower()
            if need_low and not all(n in low for n in need_low):
                continue
            res.append((_dict_score(plain, vacab), alpha, key, plain))
    res.sort(key=lambda x: -x[0])
    seen, out = set(), []
    for sc, alpha, key, plain in res:
        if plain in seen:
            continue
        seen.add(plain)
        out.append((sc, alpha, key, plain))
        if len(out) >= top:
            break
    return out


MORSE = {
    '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E', '..-.': 'F',
    '--.': 'G', '....': 'H', '..': 'I', '.---': 'J', '-.-': 'K', '.-..': 'L',
    '--': 'M', '-.': 'N', '---': 'O', '.--.': 'P', '--.-': 'Q', '.-.': 'R',
    '...': 'S', '-': 'T', '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X',
    '-.--': 'Y', '--..': 'Z', '-----': '0', '.----': '1', '..---': '2',
    '...--': '3', '....-': '4', '.....': '5', '-....': '6', '--...': '7',
    '---..': '8', '----.': '9',
}


def morse_decode(text: str) -> str:
    text = text.replace('|', '/')
    words = re.split(r'\s*/\s*|\s{2,}', text.strip())
    out = []
    for w in words:
        letters = [MORSE.get(t, '?') for t in w.split() if t]
        out.append(''.join(letters))
    return ' '.join(out)


MULTITAP = {'2': 'abc', '3': 'def', '4': 'ghi', '5': 'jkl', '6': 'mno',
            '7': 'pqrs', '8': 'tuv', '9': 'wxyz', '0': ' '}


def multitap_decode(text: str) -> str:
    out = []
    for group in re.split(r'\s+', text.strip()):
        if not group:
            continue
        if group == '0':
            out.append(' ')
            continue
        d = group[0]
        n = len(group)
        if d in MULTITAP and 1 <= n <= len(MULTITAP[d]):
            out.append(MULTITAP[d][n - 1])
    return ''.join(out)


def playfair_square(key: str):
    key = re.sub(r'[^a-z]', '', key.lower()).replace('j', 'i')
    seen = []
    for c in key + string.ascii_lowercase.replace('j', ''):
        if c not in seen:
            seen.append(c)
    return [seen[i * 5:(i + 1) * 5] for i in range(5)]


def playfair(text: str, key: str, encrypt=False) -> str:
    sq = playfair_square(key)
    pos = {sq[r][c]: (r, c) for r in range(5) for c in range(5)}
    clean = re.sub(r'[^a-z]', '', text.lower()).replace('j', 'i')
    pairs = []
    i = 0
    while i < len(clean):
        a = clean[i]
        b = clean[i + 1] if i + 1 < len(clean) else 'x'
        if a == b:
            b = 'x'
            i += 1
        else:
            i += 2
        pairs.append((a, b))
    out = []
    for a, b in pairs:
        ra, ca = pos[a]
        rb, cb = pos[b]
        d = 1 if encrypt else -1
        if ra == rb:
            out += [sq[ra][(ca + d) % 5], sq[rb][(cb + d) % 5]]
        elif ca == cb:
            out += [sq[(ra + d) % 5][ca], sq[(rb + d) % 5][cb]]
        else:
            out += [sq[ra][cb], sq[rb][ca]]
    return ''.join(out)


def index_of_coincidence(s: str) -> float:
    letters = [c.lower() for c in s if c.isalpha()]
    n = len(letters)
    if n < 2:
        return 0.0
    counts = collections.Counter(letters)
    return sum(v * (v - 1) for v in counts.values()) / (n * (n - 1))


def chi2_for_shift(col: str, shift: int) -> float:
    text = caesar(col, shift).lower()
    letters = [c for c in text if c in string.ascii_lowercase]
    n = len(letters)
    if not n:
        return 1e9
    chi = 0.0
    for c in string.ascii_lowercase:
        observed = letters.count(c) / n * 100
        chi += (observed - ENG_FREQ[c]) ** 2 / ENG_FREQ[c]
    return chi


TRIGRAMS = set("""
the and ing her tha nth int ere tio ter est ers ati hat ate all eth hes ver his
oft ith fth sth oth res ont ent ion tio for men ead eak ill ain ive ove ome one
not but you all can has was are his her its our out day get use man new now way
may say see two how who did she him his had has let put too end why try ask own
say old any few bad big low high work time year week hand part place case point
group problem fact right small large next early young important public private
 th th  he  e t  qu qui uic ick ck   k b  br bro row own wn   fo fox ox   ju jum
ump mp   ps  s o  ov ove ver er   r t  la laz azy zy   do dog og   an and nd
 fi fin ind nds  ct ctf tf{ f{a  au aut uto toc ocr cra rac ack ck_ k_c _ca cae
aes esa sar ar} r}
""".split())

COMMON_WORDS = ["the", "and", "flag", "ctf", "this", "that", "you", "with", "for",
                "are", "not", "have", "from", "was", "key", "secret", "message"]


def english_score(s: str) -> float:
    low = " " + s.lower() + " "
    grams = {}
    for i in range(len(low) - 2):
        g = low[i:i + 3]
        grams[g] = grams.get(g, 0) + 1
    sc = 0.0
    for t in TRIGRAMS:
        if t in grams:
            sc += grams[t] * (6 if t == "the" else 1)
    for w in COMMON_WORDS:
        sc += low.count(" " + w + " ") * 4
    return sc + index_of_coincidence(low) * 50


def vigenere_crack(text: str):
    letters = [c for c in text if c.isalpha()]
    if len(letters) < 40:
        return None
    max_klen = max(1, min(20, len(letters) // 20))
    results = []
    for klen in range(1, max_klen + 1):
        cols = ["".join(letters[i::klen]) for i in range(klen)]
        starts = []
        chi_key = [min(range(26), key=lambda sh: chi2_for_shift(col, sh)) for col in cols]
        freq_key = []
        for col in cols:
            col_l = [c.lower() for c in col if c.isalpha()]
            if not col_l:
                freq_key.append(0)
                continue
            top = max(string.ascii_lowercase, key=col_l.count)
            freq_key.append((ord(top) - 97 - 4) % 26)  # самая частая буква -> E
        starts = [chi_key, [(26 - s) % 26 for s in chi_key], freq_key, [0] * klen]
        for s in range(16 if klen <= 8 else 2):
            rnd = random.Random(1234 + klen * 17 + s)
            starts.append([rnd.randrange(26) for _ in range(klen)])

        best_key, best_score = None, -1e18
        for start in starts:
            key = list(start)
            current = english_score(vigenere(text, "".join(chr(65 + s) for s in key)))
            improved = True
            while improved:
                improved = False
                for pos in range(klen):
                    base = key[pos]
                    local_best, local_score = base, current
                    for sh in range(26):
                        if sh == base:
                            continue
                        key[pos] = sh
                        sc = english_score(vigenere(text, "".join(chr(65 + s) for s in key)))
                        if sc > local_score:
                            local_best, local_score = sh, sc
                    key[pos] = base
                    if local_best != base:
                        key[pos] = local_best
                        current = local_score
                        improved = True
            if current > best_score:
                best_score, best_key = current, list(key)

        key_s = "".join(chr(65 + s) for s in best_key)
        results.append((best_score, klen, key_s, vigenere(text, key_s)))

    # ключ мог определиться с лишним периодом (keylen=10 вместо 5) — сокращаем
    final = {}
    for score, klen, key_s, plain in results:
        short = key_s
        for p in range(1, klen + 1):
            if klen % p == 0 and all(key_s[i] == key_s[i % p] for i in range(klen)):
                short = key_s[:p]
                break
        cand = vigenere(text, short)
        sc = english_score(cand)
        if short not in final or sc > final[short][0]:
            final[short] = (sc, cand)
    out = [(sc, len(k), k, pl) for k, (sc, pl) in final.items()]
    out.sort(key=lambda x: -x[0])
    return out[:3]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("cipher", choices=["caesar", "affine", "vigenere", "vigenere-crack",
                                       "vigdict", "vigenere-phrase", "atbash", "morse",
                                       "multitap", "playfair"])
    ap.add_argument("--text", required=True)
    ap.add_argument("--key")
    ap.add_argument("--key-file",
                    help="файл-источник ключа для vigenere-phrase (стих, письмо)")
    ap.add_argument("--a", type=int)
    ap.add_argument("--b", type=int)
    ap.add_argument("--known")
    ap.add_argument("--words", help="словарь для vigdict (одно слово в строке)")
    ap.add_argument("--alphabet", help="свой алфавит: буквы+цифры+_ (или через запятую)")
    ap.add_argument("--need", help="в расшифровке обязаны быть эти подстроки (через запятую)")
    ap.add_argument("--top", type=int, default=10)
    ap.add_argument("--encrypt", action="store_true")
    args = ap.parse_args()

    if args.cipher == "caesar":
        if args.key is not None:
            print(caesar(args.text, int(args.key)))
        else:
            res = [(score_text(caesar(args.text, k)), k, caesar(args.text, k)) for k in range(26)]
            for s, k, t in sorted(res, reverse=True)[:8]:
                print(f"[shift {k:2d}] score={s:7.1f}  {t}")
    elif args.cipher == "affine":
        if args.a and args.b is not None:
            print(affine_dec(args.text, args.a, args.b))
        elif args.known:
            known = re.sub(r'[^a-zA-Z]', '', args.known).lower()
            hits = []
            for a in range(1, 26):
                if math.gcd(a, 26) != 1:
                    continue
                for b in range(26):
                    dec = re.sub(r'[^a-zA-Z]', '', affine_dec(args.text, a, b)).lower()
                    if dec.startswith(known):
                        hits.append((a, b, affine_dec(args.text, a, b)))
            if hits:
                for a, b, t in hits:
                    print(f"[a={a} b={b}] {t}")
            else:
                print("[-] не нашёл. Проверь префикс (только буквы) или дай --a/--b.")
        else:
            print("[-] нужен --known ПРЕФИКС или --a/--b")
    elif args.cipher == "vigenere":
        if not args.key:
            print("[-] нужен --key (без ключа используй vigenere-crack)")
            return
        if args.alphabet:
            print(vigenere_alpha(args.text, args.key, args.alphabet, args.encrypt))
        else:
            print(vigenere(args.text, args.key, args.encrypt))
    elif args.cipher == "vigdict":
        if not args.words:
            print("[-] нужен --words файл-словарь")
            return
        try:
            words = [w.strip() for w in open(args.words, encoding="utf-8",
                                             errors="replace") if w.strip()]
        except OSError as e:
            print(f"[-] не могу прочитать словарь: {e}")
            return
        alphas = [a for a in (args.alphabet or "").split(",") if a] or None
        need = [n for n in (args.need or "").split(",") if n] or None
        res = vigdict_crack(args.text, words, alphas, need, args.top)
        if not res:
            print(f"[-] ни одно слово из {len(words)} не подошло")
            if need:
                print(f"    фильтр --need {need}: попробуй без него")
            return
        for sc, alpha, key, plain in res:
            print(f"\n[score={sc:6.1f}] key={key}  алфавит={alpha}")
            print(f"  {plain[:300]}")
    elif args.cipher == "vigenere-crack":
        res = vigenere_crack(args.text)
        if not res:
            print("[-] текста слишком мало")
            return
        for sc, klen, key, plain in res:
            print(f"\n[score={sc:.1f}] keylen={klen} key={key}")
            print(plain[:600])
    elif args.cipher == "vigenere-phrase":
        if not args.key_file:
            print("[-] нужен --key-file: текст, из которого взят ключ (стих, письмо)")
            return
        try:
            source = open(args.key_file, encoding="utf-8", errors="replace").read()
        except OSError as e:
            print(f"[-] не могу прочитать источник ключа: {e}")
            return
        res = vigenere_phrase_crack(args.text, source, args.top)
        if not res:
            print("[-] в источнике не нашлось слов для ключа")
            return
        for sc, key, plain in res:
            print(f"\n[score={sc:6.1f}] key={key}  (из {os.path.basename(args.key_file)})")
            print(f"  {plain[:300]}")
    elif args.cipher == "atbash":
        table = str.maketrans(string.ascii_lowercase + string.ascii_uppercase,
                              string.ascii_lowercase[::-1] + string.ascii_uppercase[::-1])
        print(args.text.translate(table))
    elif args.cipher == "morse":
        print(morse_decode(args.text))
    elif args.cipher == "multitap":
        print(multitap_decode(args.text))
    elif args.cipher == "playfair":
        if not args.key:
            print("[-] нужен --key")
            return
        print(playfair(args.text, args.key, args.encrypt))


if __name__ == "__main__":
    main()
