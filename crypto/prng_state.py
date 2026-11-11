#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
prng_state.py — восстановление состояния предсказуемых ГПСЧ по выходам.

  mt         MT19937: 624 подряд идущих 32-битных выхода -> untemper -> клон;
             следующие и ПРЕДЫДУЩИЕ значения, getrandbits(32/64), random()
  lcg        LCG x' = a*x + c mod m: неизвестные m, a, c по нескольким выходам
             (m через gcd определителей), либо известный модуль (--m)
  lcg-trunc  LCG с усечёнными выходами (видны только старшие биты состояния):
             младшие биты через решётку (встроенный LLL + Babai)

Вход: файл (или строка) с числами: по одному в строке или через пробел/запятую.
--cipher (hex / base64 / путь к файлу) XOR-ится с предсказанным потоком, флаг
ищется в результате.

  python prng_state.py mt outs.txt --n 5 --prev 3
  python prng_state.py mt outs.txt --cipher <hex> --ks le32
  python prng_state.py lcg outs.txt --n 5
  python prng_state.py lcg outs.txt --m 2147483647 --cipher <hex> --ks low8
  python prng_state.py lcg-trunc outs.txt --m 281474976710656 --a 25214903917 \\
      --c 11 --shift 16 --n 5
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
import os
import re
import sys
from fractions import Fraction
from math import gcd, isqrt

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import common  # noqa: E402

# ---------------------------------------------------------------- ввод

NUM_RE = re.compile(r"-?(?:0[xX][0-9a-fA-F]+|\d+)")


def parse_numbers(text: str) -> list[int]:
    return [int(t, 0) if t.lower().lstrip("-").startswith("0x") else int(t)
            for t in NUM_RE.findall(text)]


def load_numbers(src: str) -> list[int]:
    """Файл с числами или сама строка с числами."""
    if os.path.isfile(src):
        try:
            with open(src, "r", encoding="utf-8", errors="replace") as f:
                return parse_numbers(f.read())
        except (PermissionError, OSError) as e:
            raise SystemExit(f"[!] не могу прочитать {src}: {e}")
    if os.path.isdir(src):
        raise SystemExit(f"[!] {src} — каталог, нужен файл с числами")
    nums = parse_numbers(src)
    if not nums:
        raise SystemExit(f"[!] файл не найден и в строке нет чисел: {src}")
    return nums


def load_cipher(s: str) -> bytes:
    raw = None
    if os.path.isfile(s):
        try:
            raw = open(s, "rb").read()
        except OSError as e:
            raise SystemExit(f"[!] cipher: {e}")
        t = raw.strip()
        if re.fullmatch(rb"(?:0x)?[0-9a-fA-F\s]+", t) and len(t.replace(b" ", b"")) % 2 == 0:
            try:
                return binascii.unhexlify(re.sub(rb"(?i)^0x|\s", b"", t))
            except binascii.Error:
                pass
        return raw
    t = s.strip()
    t = re.sub(r"(?i)^0x", "", t)
    t = re.sub(r"\s", "", t)
    if re.fullmatch(r"[0-9a-fA-F]+", t) and len(t) % 2 == 0:
        return binascii.unhexlify(t)
    try:
        return base64.b64decode(t, validate=True)
    except Exception:
        return s.encode("utf-8", "replace")


# ---------------------------------------------------------------- MT19937

_U, _L, _MAG = 0x80000000, 0x7FFFFFFF, 0x9908B0DF
_M32 = 0xFFFFFFFF


def temper(y: int) -> int:
    y ^= y >> 11
    y ^= (y << 7) & 0x9D2C5680
    y ^= (y << 15) & 0xEFC60000
    y ^= y >> 18
    return y & _M32


def _unshift_right(y: int, s: int) -> int:
    x = y
    for _ in range(32 // s + 1):
        x = y ^ (x >> s)
    return x & _M32


def _unshift_left(y: int, s: int, mask: int) -> int:
    x = y
    for _ in range(32 // s + 1):
        x = y ^ ((x << s) & mask)
    return x & _M32


def untemper(y: int) -> int:
    y &= _M32
    y = _unshift_right(y, 18)
    y = _unshift_left(y, 15, 0xEFC60000)
    y = _unshift_left(y, 7, 0x9D2C5680)
    y = _unshift_right(y, 11)
    return y


def _mix(y: int) -> int:
    return (y >> 1) ^ (_MAG if y & 1 else 0)


class MT:
    """Последовательность нетемперированных слов x_n. MT — линейная
    рекуррентность x[n+624] = x[n+397] ^ twist(x[n] верх | x[n+1] низ),
    поэтому выравнивание по блокам не нужно: клон работает с любого места."""

    def __init__(self, outputs32: list[int]):
        if len(outputs32) < 624:
            raise ValueError("нужно минимум 624 подряд идущих 32-битных выхода")
        self.x = [untemper(v) for v in outputs32]

    def consistent(self) -> tuple[int, int]:
        """Проверка рекуррентности на лишних выходах: (совпало, проверено)."""
        x, ok, tot = self.x, 0, 0
        for n in range(len(x) - 624):
            y = (x[n] & _U) | (x[n + 1] & _L)
            tot += 1
            ok += x[n + 624] == (x[n + 397] ^ _mix(y))
        return ok, tot

    def forward(self, count: int) -> list[int]:
        """Следующие count выходов (темперированные)."""
        x = list(self.x[-624:])
        out = []
        for _ in range(count):
            y = (x[-624] & _U) | (x[-623] & _L)
            nv = x[-227] ^ _mix(y)
            x.append(nv)
            out.append(temper(nv))
        return out

    def backward(self, count: int) -> list[int]:
        """count выходов, предшествующих первому известному (в порядке выдачи)."""
        w = list(self.x[:624])
        res = []
        for _ in range(count):
            # w[0..623] = x[s..s+623]; ищем x[s-1] = p
            # x[s+623] = x[s+396] ^ mix((p & U) | (x[s] & L))
            t = w[623] ^ w[396]
            if t & _U:
                t ^= _MAG
                y = ((t << 1) | 1) & _M32
            else:
                y = (t << 1) & _M32
            low_of_y_hi = y & _U          # верхний бит p
            # x[s+624-1]... верхний бит p берём из уравнения для x[s+623-?]:
            # x[s-1+624] = x[s-1+397] ^ mix((p&U)|(x[s]&L)); x[s+623] это оно.
            # Нижние 31 бит p: из уравнения для x[s+622]:
            # x[s+622] = x[s+395] ^ mix((x[s-2]&U)|(p&L))
            t2 = w[622] ^ w[395]
            if t2 & _U:
                t2 ^= _MAG
                y2 = ((t2 << 1) | 1) & _M32
            else:
                y2 = (t2 << 1) & _M32
            p = low_of_y_hi | (y2 & _L)
            w.insert(0, p)
            w.pop()
            res.append(temper(p))
        res.reverse()
        return res


def words_to_bits(words: list[int], k: int) -> list[int]:
    """random.getrandbits(k) для k>=1 подряд из потока 32-битных слов."""
    out, i = [], 0
    nw = (k + 31) // 32
    while i + nw <= len(words):
        if k <= 32:
            out.append(words[i] >> (32 - k))
        else:
            v, rem = 0, k
            for j in range(nw):
                w = words[i + j]
                if rem < 32:
                    w >>= 32 - rem
                v |= w << (32 * j)
                rem -= 32
            out.append(v)
        i += nw
    return out


def words_to_doubles(words: list[int]) -> list[float]:
    """random.random(): (a>>5)*2^26 + (b>>6) пары слов."""
    return [((words[i] >> 5) * 67108864 + (words[i + 1] >> 6)) / 9007199254740992.0
            for i in range(0, len(words) - 1, 2)]


def to_words(nums: list[int], bits: int) -> list[int]:
    """Выходы -> поток 32-битных слов. 64: младшее слово первым (getrandbits(64))."""
    if bits == 64:
        w = []
        for v in nums:
            w += [v & _M32, (v >> 32) & _M32]
        return w
    return [v & _M32 for v in nums]


# ---------------------------------------------------------------- keystream

def ks_bytes(vals: list[int], mode: str, width: int, nbits: int) -> bytes:
    """Из значений генератора — байты потока.
    le/be: целое в width байт; low8: v & 255; high8: старшие 8 бит из nbits;
    mod256: v % 256."""
    out = bytearray()
    for v in vals:
        if mode == "le":
            out += (v & ((1 << (8 * width)) - 1)).to_bytes(width, "little")
        elif mode == "be":
            out += (v & ((1 << (8 * width)) - 1)).to_bytes(width, "big")
        elif mode == "low8":
            out.append(v & 255)
        elif mode == "high8":
            out.append((v >> max(nbits - 8, 0)) & 255)
        elif mode == "mod256":
            out.append(v % 256)
        else:
            raise ValueError(mode)
    return bytes(out)


def mt_randbytes(words: list[int], n: int) -> bytes:
    """random.randbytes(n) == getrandbits(8n).to_bytes(n, 'little')."""
    nw = (n + 3) // 4
    if len(words) < nw:
        raise ValueError("мало слов")
    v = words_to_bits(words[:nw], 32 * nw)[0] if nw else 0
    if n % 4:
        v = 0
        rem = 8 * n
        for j in range(nw):
            w = words[j]
            if rem < 32:
                w >>= 32 - rem
            v |= w << (32 * j)
            rem -= 32
    return v.to_bytes(n, "little")


def xor_report(cipher: bytes, stream: bytes, label: str) -> bool:
    n = min(len(cipher), len(stream))
    plain = bytes(c ^ s for c, s in zip(cipher[:n], stream[:n]))
    shown = plain.decode("utf-8", "replace")
    flags = common.find_flags(plain)
    print(f"[i] {label}: {shown[:300]!r}")
    for f in flags:
        print(f"[+] FLAG: {f}")
    return bool(flags)


# ---------------------------------------------------------------- LCG

def modinv(a: int, m: int):
    try:
        return pow(a, -1, m)
    except ValueError:
        return None


def lcg_fits(xs: list[int], m: int, a: int, c: int) -> bool:
    return all((a * xs[i] + c) % m == xs[i + 1] % m for i in range(len(xs) - 1))


def solve_ac(xs: list[int], m: int):
    """Все (a, c) для известного модуля, согласованные с xs."""
    res = []
    t = [(xs[i + 1] - xs[i]) % m for i in range(len(xs) - 1)]
    # t[i+1] = a * t[i]  (mod m)
    cands = None
    for i in range(len(t) - 1):
        g = gcd(t[i], m)
        if t[i + 1] % g:
            return []
        m2 = m // g
        if m2 == 1:
            continue
        inv = modinv(t[i] // g % m2, m2)
        if inv is None:
            continue
        a0 = (t[i + 1] // g) * inv % m2
        step_cands = {a0 + k * m2 for k in range(g)} if g <= 4096 else None
        if step_cands is None:
            continue
        cands = step_cands if cands is None else cands & step_cands
    if cands is None:
        # данные вырождены: пробуем a по x[2]-x[1] / x[1]-x[0] если обратим
        cands = set()
        if len(t) >= 2:
            inv = modinv(t[0], m)
            if inv is not None:
                cands.add(t[1] * inv % m)
    for a in sorted(cands):
        c = (xs[1] - a * xs[0]) % m
        if lcg_fits(xs, m, a, c):
            res.append((a, c))
    return res


def recover_modulus(xs: list[int]):
    """Кандидаты модуля: gcd(t[i+2]*t[i] - t[i+1]^2), затем снятие малых множителей."""
    t = [xs[i + 1] - xs[i] for i in range(len(xs) - 1)]
    g = 0
    for i in range(len(t) - 2):
        g = gcd(g, t[i + 2] * t[i] - t[i + 1] * t[i + 1])
    g = abs(g)
    if g == 0:
        return []
    lo = max(xs) + 1
    out = []
    for d in range(1, 100001):
        if g % d:
            continue
        m = g // d
        if m < lo:
            break
        out.append(m)
    return out


def lcg_recover(xs: list[int], m=None):
    """-> список (m, a, c)."""
    sols = []
    mods = [m] if m else recover_modulus(xs)
    for mm in mods:
        if mm < 2:
            continue
        for a, c in solve_ac([x % mm for x in xs], mm):
            sols.append((mm, a, c))
        if sols and not m:
            break
    return sols


# ---------------------------------------------------------------- LLL + Babai

def lll(B: list[list[int]], delta=Fraction(3, 4)) -> list[list[int]]:
    """Простая точная LLL-редукция (Fraction) — для малых размерностей."""
    B = [list(r) for r in B]
    n = len(B)

    def dot(u, v):
        return sum(x * y for x, y in zip(u, v))

    def gs():
        Bs, mu = [], [[Fraction(0)] * n for _ in range(n)]
        for i in range(n):
            v = [Fraction(x) for x in B[i]]
            for j in range(i):
                mu[i][j] = dot(B[i], Bs[j]) / dot(Bs[j], Bs[j]) if any(Bs[j]) else Fraction(0)
                v = [a - mu[i][j] * b for a, b in zip(v, Bs[j])]
            Bs.append(v)
        return Bs, mu

    Bs, mu = gs()
    k = 1
    while k < n:
        for j in range(k - 1, -1, -1):
            q = round(mu[k][j])
            if q:
                B[k] = [a - q * b for a, b in zip(B[k], B[j])]
                Bs, mu = gs()
        if dot(Bs[k], Bs[k]) >= (delta - mu[k][k - 1] ** 2) * dot(Bs[k - 1], Bs[k - 1]):
            k += 1
        else:
            B[k], B[k - 1] = B[k - 1], B[k]
            Bs, mu = gs()
            k = max(k - 1, 1)
    return B


def babai(B: list[list[int]], target: list[int]) -> list[int]:
    """Ближайший вектор решётки к target (nearest plane); B уже LLL-редуцирован."""
    n = len(B)
    Bs = []
    for i in range(n):
        v = [Fraction(x) for x in B[i]]
        for j in range(i):
            d = sum(x * x for x in Bs[j])
            mu = sum(Fraction(a) * b for a, b in zip(B[i], Bs[j])) / d
            v = [a - mu * b for a, b in zip(v, Bs[j])]
        Bs.append(v)
    t = [Fraction(x) for x in target]
    res = [0] * len(target)
    for i in range(n - 1, -1, -1):
        d = sum(x * x for x in Bs[i])
        c = round(sum(a * b for a, b in zip(t, Bs[i])) / d)
        t = [a - c * b for a, b in zip(t, B[i])]
        res = [a + c * b for a, b in zip(res, B[i])]
    return res


def lcg_trunc_recover(ys: list[int], m: int, a: int, c: int, shift: int):
    """Состояния x_i (полные) по старшим битам y_i = x_i >> shift. -> список x или None."""
    bound = 1 << shift
    lm = max(m.bit_length(), 1)
    per = max(lm - shift, 1)
    n0 = min(len(ys), max(3, lm // per + 2))
    for n in range(n0, min(len(ys), n0 + 6) + 1):
        xs = _trunc_try(ys[:n], m, a, c, shift, bound)
        if xs is not None:
            # проверка на всех данных
            full = [xs[0]]
            for _ in range(len(ys) - 1):
                full.append((a * full[-1] + c) % m)
            if all((full[i] >> shift) == ys[i] for i in range(len(ys))):
                return full
    return None


def _trunc_try(ys, m, a, c, shift, bound):
    n = len(ys)
    half = bound // 2
    Yc = [(y << shift) + half for y in ys]          # центр интервала
    # d_i: e_{i+1} - a e_i = -(Yc_{i+1} - a Yc_i - c)  mod m
    d = [(-(Yc[i + 1] - a * Yc[i] - c)) % m for i in range(n - 1)]
    s = [0] * n
    for i in range(1, n):
        s[i] = (a * s[i - 1] + d[i - 1]) % m
    pw = [pow(a, i, m) for i in range(n)]
    K = max(half, 1)
    dim = n + 1
    B = [[pw[i] for i in range(n)] + [0]]
    for i in range(1, n):
        row = [0] * dim
        row[i] = m
        B.append(row)
    B.append([s[i] for i in range(n)] + [K])        # embedding-строка
    R = lll(B)
    # ищем вектор с последней координатой ±K и малыми остальными
    for r in R:
        if abs(r[-1]) == K:
            sign = 1 if r[-1] == K else -1
            e = [sign * v for v in r[:-1]]
            if all(abs(v) <= bound for v in e):
                x0 = Yc[0] + e[0]
                if 0 <= x0 < m and (x0 >> shift) == ys[0]:
                    return [x0]
    # запасной путь: Babai на решётке без embedding-строки
    L = lll(B[:-1])
    v = babai(L, [(-x) for x in s])
    e = [s[i] + v[i] for i in range(n)]
    x0 = Yc[0] + e[0]
    if all(abs(t) <= bound for t in e) and 0 <= x0 < m and (x0 >> shift) == ys[0]:
        return [x0]
    return None


# ---------------------------------------------------------------- команды

def pick_ks(args, default_width: int):
    mode = args.ks or "le"
    width = args.width or default_width
    return mode, width


def cmd_mt(args) -> int:
    nums = load_numbers(args.src)
    bits = args.bits
    if bits == 0:
        bits = 64 if max(nums) > _M32 else 32
    words = to_words(nums, bits)
    print(f"[i] чисел: {len(nums)}, разрядность {bits}, слов по 32 бита: {len(words)}")
    if len(words) < 624:
        print(f"[!] нужно >= 624 слов (есть {len(words)}): состояние не восстановить")
        return 1
    mt = MT(words)
    ok, tot = mt.consistent()
    if tot:
        print(f"[i] проверка рекуррентности на лишних выходах: {ok}/{tot}")
        if ok != tot:
            print("[!] выходы НЕ согласованы с MT19937 (разрыв, чужой генератор "
                  "или не подряд идущие)")
            return 1
    else:
        print("[i] ровно 624 слова — проверить клон нельзя, предсказание по определению")
    cl = (len(load_cipher(args.cipher)) + 3) // 4 + args.skip + 8 if args.cipher else 0
    nxt = mt.forward(max(args.n, cl))
    prv = mt.backward(args.prev) if args.prev else []
    shown_next = nxt[:args.n]
    if bits == 64:
        print("[+] следующие getrandbits(64):",
              words_to_bits(shown_next, 64)[: args.n // 2 or 1])
    print("[+] следующие getrandbits(32):", shown_next)
    print("[+] следующие random():", words_to_doubles(shown_next)[: max(args.n // 2, 1)])
    if prv:
        print("[+] предыдущие (getrandbits(32), в порядке выдачи):", prv)
    if args.cipher:
        c = load_cipher(args.cipher)
        found = False
        nw = (len(c) + 3) // 4
        before = mt.backward(nw + args.skip + 8) if args.when == "before" else []
        for skip in range(0, args.skip + 1):
            if args.when == "before":
                ws = before[:len(before) - skip][-nw:]
            else:
                ws = nxt[skip:]
            cands = []
            if args.ks in (None, "randbytes"):
                try:
                    cands.append(("randbytes", mt_randbytes(ws, len(c))))
                except ValueError:
                    pass
            for mode in ([args.ks] if args.ks and args.ks != "randbytes" else ["le", "be", "low8"]):
                cands.append((mode, ks_bytes(ws, mode, args.width or 4, 32)))
            for label, st in cands:
                found |= xor_report(c, st, f"{label} (skip={skip}, {args.when})")
            if found:
                break
        if not found:
            print("[i] флаг в XOR не найден (смотри --ks/--skip/--when before)")
    return 0


def cmd_lcg(args) -> int:
    xs = load_numbers(args.src)
    print(f"[i] выходов: {len(xs)}")
    if args.a is not None and args.c is not None and args.m:
        sols = [(args.m, args.a, args.c)] if lcg_fits(xs, args.m, args.a, args.c) else []
        if not sols:
            print("[!] заданные a/c/m не согласуются с выходами")
            return 1
    elif args.a is not None and args.m:
        c = (xs[1] - args.a * xs[0]) % args.m
        sols = [(args.m, args.a, c)] if lcg_fits(xs, args.m, args.a, c) else []
    else:
        if len(xs) < (3 if args.m else 6):
            print("[!] мало выходов: для неизвестного модуля нужно >= 6, для известного >= 3")
            return 1
        sols = lcg_recover(xs, args.m)
    if not sols:
        print("[!] LCG не восстановлен (не линейный конгруэнтный или слишком мало данных)")
        return 1
    done = False
    for m, a, c in sols[:3]:
        print(f"[+] m = {m}\n[+] a = {a}\n[+] c = {c}")
        x = xs[-1]
        nxt = []
        for _ in range(args.n):
            x = (a * x + c) % m
            nxt.append(x)
        print("[+] следующие:", nxt)
        ai = modinv(a, m)
        if args.prev and ai is not None:
            x, prv = xs[0], []
            for _ in range(args.prev):
                x = ai * (x - c) % m
                prv.append(x)
            print("[+] предыдущие (от ближайшего к далёким):", prv)
        elif args.prev:
            print("[i] a необратим по модулю m — назад не считаем")
        if args.cipher:
            c_b = load_cipher(args.cipher)
            width = args.width or max((m.bit_length() + 7) // 8, 1)
            modes = [args.ks] if args.ks else ["le", "be", "low8", "high8", "mod256"]
            need = len(c_b) if args.ks in ("low8", "high8", "mod256") else (len(c_b) + width - 1) // width
            fut, x = [], xs[-1]
            for _ in range(need + args.skip + 2):
                x = (a * x + c) % m
                fut.append(x)
            past, x = [], xs[0]
            if ai is not None and args.when == "before":
                for _ in range(need + args.skip + 2):
                    x = ai * (x - c) % m
                    past.append(x)
                past.reverse()
            for skip in range(0, args.skip + 1):
                seq = (past[:len(past) - skip] if args.when == "before" else fut[skip:])
                if args.when == "before":
                    seq = seq[-need:]
                for mode in modes:
                    done |= xor_report(c_b, ks_bytes(seq, mode, width, m.bit_length()),
                                       f"{mode} (skip={skip}, {args.when})")
                if done:
                    break
    if args.cipher and not done:
        print("[i] флаг в XOR не найден (смотри --ks/--width/--skip/--when before)")
    return 0


def cmd_lcg_trunc(args) -> int:
    ys = load_numbers(args.src)
    if args.m is None or args.a is None or args.c is None:
        print("[!] lcg-trunc: нужны известные --m --a --c (и --shift или --out-bits)")
        return 1
    m = args.m
    shift = args.shift
    if shift is None:
        if args.out_bits is None:
            print("[!] укажи --shift (сколько младших бит скрыто) или --out-bits")
            return 1
        shift = m.bit_length() - 1 - args.out_bits if m & (m - 1) == 0 else \
            m.bit_length() - args.out_bits
    if shift < 0:
        print("[!] shift < 0")
        return 1
    if shift == 0:
        full = ys
    else:
        print(f"[i] выходов: {len(ys)}, m: {m.bit_length()} бит, скрыто младших бит: {shift}")
        full = lcg_trunc_recover(ys, m, args.a, args.c, shift)
    if not full:
        print("[!] состояние не восстановлено: мало выходов (нужно n*(log2 m - shift) > "
              "log2 m + запас) или неверные параметры")
        return 1
    print(f"[+] полное состояние x0 = {full[0]}")
    print(f"[+] текущее состояние (после последнего выхода) = {full[-1]}")
    x, nxt = full[-1], []
    nvals = max(args.n, 0)
    cipher = load_cipher(args.cipher) if args.cipher else None
    width = args.width or max(((m.bit_length() - shift) + 7) // 8, 1)
    need = nvals
    if cipher is not None:
        need = max(nvals, len(cipher) + args.skip + 4)
    for _ in range(need):
        x = (args.a * x + args.c) % m
        nxt.append(x >> shift)
    print("[+] следующие (старшие биты):", nxt[:nvals])
    if cipher is not None:
        modes = [args.ks] if args.ks else ["le", "be", "low8", "high8"]
        done = False
        for skip in range(0, args.skip + 1):
            seq = nxt[skip:]
            for mode in modes:
                done |= xor_report(cipher, ks_bytes(seq, mode, width, m.bit_length() - shift),
                                   f"{mode} (skip={skip})")
            if done:
                break
        if not done:
            print("[i] флаг в XOR не найден (смотри --ks/--width/--skip)")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="восстановление состояния ГПСЧ (MT19937, LCG)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    def common_args(p):
        p.add_argument("src", help="файл с числами (или строка чисел)")
        p.add_argument("--n", type=int, default=10, help="сколько значений предсказать вперёд")
        p.add_argument("--prev", type=int, default=0, help="сколько значений назад")
        p.add_argument("--cipher", help="шифртекст (hex/base64/файл) для XOR с потоком")
        p.add_argument("--ks", choices=["le", "be", "low8", "high8", "mod256", "randbytes"],
                       help="как превращать выходы в байты потока (по умолчанию перебор)")
        p.add_argument("--width", type=int, help="байт на выход для le/be")
        p.add_argument("--skip", type=int, default=0,
                       help="перебрать пропуск до N выходов перед потоком")
        p.add_argument("--when", choices=["after", "before"], default="after",
                       help="шифртекст зашифрован ПОСЛЕ или ДО известных выходов")
        common.add_flag_args(p)

    p = sub.add_parser("mt", help="MT19937 по 624 выходам")
    common_args(p)
    p.add_argument("--bits", type=int, choices=[0, 32, 64], default=0,
                   help="разрядность чисел во входе (0 — по значениям)")
    p.set_defaults(fn=cmd_mt)

    p = sub.add_parser("lcg", help="LCG: m, a, c по выходам")
    common_args(p)
    p.add_argument("--m", type=int, help="известный модуль")
    p.add_argument("--a", type=int, help="известный множитель")
    p.add_argument("--c", type=int, help="известное приращение")
    p.set_defaults(fn=cmd_lcg)

    p = sub.add_parser("lcg-trunc", help="LCG с усечёнными выходами (решётка)")
    common_args(p)
    p.add_argument("--m", type=int)
    p.add_argument("--a", type=int)
    p.add_argument("--c", type=int)
    p.add_argument("--shift", type=int, help="сколько младших бит скрыто (y = x >> shift)")
    p.add_argument("--out-bits", type=int, help="сколько старших бит видно")
    p.set_defaults(fn=cmd_lcg_trunc)

    args = ap.parse_args()
    common.apply_flag_args(args)
    try:
        return args.fn(args)
    except (FileNotFoundError, IsADirectoryError, PermissionError) as e:
        print(f"[!] {e}")
        return 2


if __name__ == "__main__":
    sys.exit(main())
