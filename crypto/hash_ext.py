#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""hash_ext.py — length extension (MD5/SHA1/SHA256) и повтор nonce в GCM.

  # length extension: знаем digest(key || data), длину key и что дописать
  python hash_ext.py length-extend --alg md5 --sig 6f4b... \
      --data "user=guest" --key-len 16 --append "&admin=1"

  # повтор nonce в AES-GCM: два сообщения с одним nonce
  python hash_ext.py gcm-nonce-reuse --ct1 ... --tag1 ... --ct2 ... --tag2 ...
  # если известен открытый текст первого сообщения — расшифруем второе
  python hash_ext.py gcm-nonce-reuse ... --pt1 "hello"
  # и можно подделать тег для нового сообщения с тем же nonce
  python hash_ext.py gcm-nonce-reuse ... --forge-ct aabb --forge-aad ""
"""
from __future__ import annotations

try:
    import sys as _sys
    for _stream in (_sys.stdout, _sys.stderr):
        _stream.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

import argparse
import hashlib
import random
import struct
import sys

# ---------------------------------------------------------------- helpers


def hx(text: str) -> bytes:
    s = (text or "").strip().replace(" ", "").replace("\n", "")
    if s.lower().startswith("0x"):
        s = s[2:]
    if len(s) % 2:
        s = "0" + s
    return bytes.fromhex(s)


def to_bytes(value: str, is_hex: bool) -> bytes:
    return hx(value) if is_hex else (value or "").encode()


def merkle_pad(nbytes: int, little: bool = False) -> bytes:
    """0x80 + нули + 64-битная длина в битах (MD5 — little, SHA — big)."""
    bits = nbytes * 8
    pad = b"\x80" + b"\x00" * ((56 - (nbytes + 1) % 64) % 64)
    return pad + struct.pack("<Q" if little else ">Q", bits)


def rotl(x, n):
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def rotr(x, n):
    return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF


# ---------------------------------------------------------------- MD5

MD5_S = ([7, 12, 17, 22] * 4 + [5, 9, 14, 20] * 4
         + [4, 11, 16, 23] * 4 + [6, 10, 15, 21] * 4)
MD5_K = [int(abs(__import__("math").sin(i + 1)) * 2 ** 32) & 0xFFFFFFFF
         for i in range(64)]


def md5_compress(state, block):
    a, b, c, d = state
    m = struct.unpack("<16I", block)
    A, B, C, D = a, b, c, d
    for i in range(64):
        if i < 16:
            f = (B & C) | (~B & D)
            g = i
        elif i < 32:
            f = (D & B) | (~D & C)
            g = (5 * i + 1) % 16
        elif i < 48:
            f = B ^ C ^ D
            g = (3 * i + 5) % 16
        else:
            f = C ^ (B | (~D & 0xFFFFFFFF))
            g = (7 * i) % 16
        f = (f + A + MD5_K[i] + m[g]) & 0xFFFFFFFF
        A, D, C, B = D, C, B, (B + rotl(f, MD5_S[i])) & 0xFFFFFFFF
    return [(x + y) & 0xFFFFFFFF for x, y in zip((a, b, c, d), (A, B, C, D))]


# ---------------------------------------------------------------- SHA1


def sha1_compress(state, block):
    w = list(struct.unpack(">16I", block))
    for i in range(16, 80):
        w.append(rotl(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1))
    a, b, c, d, e = state
    for i in range(80):
        if i < 20:
            f, k = (b & c) | (~b & d), 0x5A827999
        elif i < 40:
            f, k = b ^ c ^ d, 0x6ED9EBA1
        elif i < 60:
            f, k = (b & c) | (b & d) | (c & d), 0x8F1BBCDC
        else:
            f, k = b ^ c ^ d, 0xCA62C1D6
        f &= 0xFFFFFFFF
        tmp = (rotl(a, 5) + f + e + k + w[i]) & 0xFFFFFFFF
        e, d, c, b, a = d, c, rotl(b, 30), a, tmp
    return [(x + y) & 0xFFFFFFFF for x, y in zip(state, (a, b, c, d, e))]


# ---------------------------------------------------------------- SHA256

SHA256_K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]


def sha256_compress(state, block):
    w = list(struct.unpack(">16I", block))
    for i in range(16, 64):
        s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3)
        s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10)
        w.append((w[i - 16] + s0 + w[i - 7] + s1) & 0xFFFFFFFF)
    a, b, c, d, e, f, g, h = state
    for i in range(64):
        S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)
        ch = (e & f) ^ (~e & g)
        t1 = (h + S1 + ch + SHA256_K[i] + w[i]) & 0xFFFFFFFF
        S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)
        maj = (a & b) ^ (a & c) ^ (b & c)
        t2 = (S0 + maj) & 0xFFFFFFFF
        h, g, f, e = g, f, e, (d + t1) & 0xFFFFFFFF
        d, c, b, a = c, b, a, (t1 + t2) & 0xFFFFFFFF
    return [(x + y) & 0xFFFFFFFF for x, y in zip(state, (a, b, c, d, e, f, g, h))]


ALGS = {
    "md5": (md5_compress, "<4I", hashlib.md5),
    "sha1": (sha1_compress, ">5I", hashlib.sha1),
    "sha256": (sha256_compress, ">8I", hashlib.sha256),
}


def run_state(compress, state, data: bytes):
    for off in range(0, len(data), 64):
        state = compress(state, data[off:off + 64])
    return state


def state_from_digest(alg: str, digest: bytes):
    compress, fmt, _ = ALGS[alg]
    return list(struct.unpack(fmt, digest))


def digest_from_state(alg: str, state) -> bytes:
    _, fmt, _ = ALGS[alg]
    return struct.pack(fmt, *state)


def cmd_length_extend(args):
    alg = args.alg.lower()
    if alg not in ALGS:
        print(f"[-] неизвестный алгоритм: {alg}")
        return 2
    data = to_bytes(args.data, args.data_hex) if args.data is not None else b""
    append = to_bytes(args.append, args.append_hex)
    sig = hx(args.sig)
    state = state_from_digest(alg, sig)

    little = alg == "md5"
    glue = merkle_pad(args.key_len + len(data), little)
    forged_suffix = data + glue + append
    total = args.key_len + len(forged_suffix)
    tail = append + merkle_pad(total, little)
    new_state = run_state(ALGS[alg][0], state, tail)
    new_digest = digest_from_state(alg, new_state)

    # самопроверка, если известен ключ
    if args.key_hex is not None:
        key = hx(args.key_hex)
        real = ALGS[alg][2](key + forged_suffix).hexdigest()
        print(f"[i] самопроверка: {'ok' if real == new_digest.hex() else 'НЕ СОВПАЛО'}")

    print(f"[+] алгоритм      : {alg}")
    print(f"[+] длина ключа   : {args.key_len}")
    print(f"[+] исходные данные (hex): {data.hex()}")
    print(f"[+] padding (hex) : {glue.hex()}")
    print(f"[+] дописать (hex): {append.hex()}")
    print(f"[+] сообщение после ключа (hex): {forged_suffix.hex()}")
    print(f"[+] сообщение после ключа (repr): {forged_suffix!r}")
    print(f"[+] новый digest  : {new_digest.hex()}")
    print(f"[+] всего байт    : {total}")
    if args.out:
        open(args.out, "wb").write(forged_suffix)
        print(f"[+] suffix записан в {args.out}")
    return 0


# ---------------------------------------------------------------- GCM

GF_POLY = (1 << 128) | 0x87


def bitrev128(x: int) -> int:
    r = 0
    for _ in range(128):
        r = (r << 1) | (x & 1)
        x >>= 1
    return r


def gf_mul(a: int, b: int) -> int:
    """Умножение в GF(2^128), обычный полиномиальный базис (x^0 = младший бит)."""
    z = 0
    while b:
        if b & 1:
            z ^= a
        b >>= 1
        a <<= 1
        if a >> 128:
            a ^= GF_POLY
    return z


def gf_inv(x: int) -> int:
    # x^(2^128 - 2)
    result = 1
    base = x
    for _ in range(127):
        base = gf_mul(base, base)
        result = gf_mul(result, base)
    return result


# полиномы над GF(2^128): список коэффициентов, младший первый


def ptrim(p):
    while len(p) > 1 and p[-1] == 0:
        p.pop()
    return p


def pdeg(p):
    p = ptrim(list(p))
    return len(p) - 1


def pmod(a, f):
    a = ptrim(list(a))
    f = ptrim(list(f))
    df = len(f) - 1
    inv = 1 if f[-1] == 1 else gf_inv(f[-1])
    while len(a) - 1 >= df and any(a):
        shift = len(a) - 1 - df
        coef = a[-1] if inv == 1 else gf_mul(a[-1], inv)
        for i, fc in enumerate(f):
            a[i + shift] ^= gf_mul(coef, fc)
        ptrim(a)
    return a or [0]


def pmul(a, b):
    out = [0] * (len(a) + len(b) - 1)
    for i, x in enumerate(a):
        if x:
            for j, y in enumerate(b):
                if y:
                    out[i + j] ^= gf_mul(x, y)
    return ptrim(out)


def pmulmod(a, b, f):
    return pmod(pmul(a, b), f)


def ppowmod(a, e, f):
    result = [1]
    base = pmod(a, f)
    while e:
        if e & 1:
            result = pmulmod(result, base, f)
        base = pmulmod(base, base, f)
        e >>= 1
    return result


def pdiv(a, b):
    a = ptrim(list(a))
    b = ptrim(list(b))
    db = len(b) - 1
    inv = 1 if b[-1] == 1 else gf_inv(b[-1])
    q = [0] * max(1, len(a) - db)
    while len(a) - 1 >= db and any(a):
        shift = len(a) - 1 - db
        coef = a[-1] if inv == 1 else gf_mul(a[-1], inv)
        q[shift] = coef
        for i, bc in enumerate(b):
            a[i + shift] ^= gf_mul(coef, bc)
        ptrim(a)
    return ptrim(q)


def pgcd(a, b):
    a = ptrim(list(a))
    b = ptrim(list(b))
    while any(b):
        a, b = b, pmod(a, b)
    if not any(a):
        return [0]
    inv = gf_inv(a[-1])
    return ptrim([gf_mul(c, inv) for c in a])


def p_add(a, b):
    n = max(len(a), len(b))
    out = [0] * n
    for i in range(n):
        out[i] = (a[i] if i < len(a) else 0) ^ (b[i] if i < len(b) else 0)
    return ptrim(out)


def _gcm_blocks(aad: bytes, ct: bytes):
    blocks = []
    aad_pad = aad + b"\x00" * ((16 - len(aad) % 16) % 16)
    ct_pad = ct + b"\x00" * ((16 - len(ct) % 16) % 16)
    blocks += [int.from_bytes(aad_pad[i:i + 16], "big")
               for i in range(0, len(aad_pad), 16)]
    blocks += [int.from_bytes(ct_pad[i:i + 16], "big")
               for i in range(0, len(ct_pad), 16)]
    blocks.append(((len(aad) * 8) << 64) | (len(ct) * 8))
    return blocks


def ghash_poly(aad: bytes, ct: bytes):
    """GHASH как полином по H (в обычном базисе, после bitrev)."""
    blocks = _gcm_blocks(aad, ct)
    n = len(blocks)
    poly = [0] * (n + 1)
    for i, block in enumerate(blocks):
        poly[n - i] ^= bitrev128(block)
    return poly


def ghash(h: int, aad: bytes, ct: bytes) -> int:
    hg = bitrev128(h)
    acc = 0
    for block in _gcm_blocks(aad, ct):
        acc = gf_mul(acc ^ bitrev128(block), hg)
    return bitrev128(acc)


def split_linear(g):
    """g — произведение различных линейных множителей. Возвращает корни."""
    d = pdeg(g)
    if d <= 0:
        return []
    if d == 1:
        # x + c = 0 -> x = c
        c = gf_mul(g[0], gf_inv(g[1])) if g[1] != 1 else g[0]
        return [c]
    rnd = random.Random(0xC0FFEE)
    for _ in range(200):
        a = [rnd.getrandbits(128) for _ in range(d)]
        a[0] |= 1
        trace = [0]
        cur = a
        for _ in range(128):
            trace = p_add(trace, cur)
            cur = pmulmod(cur, cur, g)
        for cand in (trace, p_add(trace, [1])):
            h = pgcd(g, cand)
            hd = pdeg(h)
            if 0 < hd < d:
                q = pdiv(g, h)
                return split_linear(h) + split_linear(q)
    return []


def roots_mod_x_q_minus_x(f):
    """Корни f в GF(2^128): gcd(f, x^(2^128)-x), затем разбиение."""
    f = ptrim(list(f))
    if pdeg(f) <= 0:
        return []
    inv = gf_inv(f[-1])
    f = ptrim([gf_mul(c, inv) for c in f])
    if pdeg(f) == 1:
        return [f[0]]
    xp = pmod([0, 1], f)
    for _ in range(128):
        xp = pmulmod(xp, xp, f)
    g = pgcd(f, p_add(xp, [0, 1]))
    if pdeg(g) <= 0:
        return []
    return split_linear(g)


def _diff_roots(aad1, ct1, tag1, aad2, ct2, tag2):
    """Корни bitrev(H) из tag1 ^ tag2 = GHASH1(H) ^ GHASH2(H)."""
    p = p_add(ghash_poly(aad1, ct1), ghash_poly(aad2, ct2))
    p[0] ^= bitrev128(int.from_bytes(tag1, "big")
                      ^ int.from_bytes(tag2, "big"))
    if not any(p):
        return set()
    return set(roots_mod_x_q_minus_x(p))


def cmd_gcm(args):
    ct1, ct2 = hx(args.ct1), hx(args.ct2)
    tag1, tag2 = hx(args.tag1), hx(args.tag2)
    aad1 = hx(args.aad1) if args.aad1 else b""
    aad2 = hx(args.aad2) if args.aad2 else b""
    if len(tag1) != 16 or len(tag2) != 16:
        print("[-] тег должен быть 16 байт")
        return 2

    t1 = int.from_bytes(tag1, "big")
    t2 = int.from_bytes(tag2, "big")
    roots = _diff_roots(aad1, ct1, tag1, aad2, ct2, tag2)
    if args.ct3:
        ct3, tag3 = hx(args.ct3), hx(args.tag3)
        aad3 = hx(args.aad3) if args.aad3 else b""
        if len(tag3) != 16:
            print("[-] тег 3 должен быть 16 байт")
            return 2
        roots &= _diff_roots(aad1, ct1, tag1, aad3, ct3, tag3)
    if not roots:
        print("[-] H не восстановился")
        return 2

    good = []
    for bh in roots:
        h = bitrev128(bh)
        if ghash(h, aad1, ct1) ^ ghash(h, aad2, ct2) == t1 ^ t2:
            good.append(h)
    if not good:
        print("[-] H не восстановился (нет корней, удовлетворяющих тегам)")
        return 2
    if len(good) > 1:
        print(f"[!] кандидатов H: {len(good)} — добавь третий пакет "
              f"(--ct3/--tag3), чтобы оставить один")

    for h in good:
        print(f"[+] H = {h:032x}")
        ej0 = t1 ^ ghash(h, aad1, ct1)
        print(f"[+] E(J0) = {ej0:032x}")

        if args.pt1 is not None:
            pt1 = to_bytes(args.pt1, args.pt1_hex)
            if len(pt1) != len(ct1):
                print(f"[-] pt1 длиной {len(pt1)}, а ct1 {len(ct1)}")
                continue
            keystream = bytes(a ^ b for a, b in zip(pt1, ct1))
            n = min(len(ct2), len(keystream))
            pt2 = bytes(a ^ b for a, b in zip(ct2[:n], keystream[:n]))
            if n < len(ct2):
                print(f"[!] известен только префикс: {n} из {len(ct2)} байт")
            print(f"[+] plaintext2 hex : {pt2.hex()}")
            print(f"[+] plaintext2 text: {pt2.decode('utf-8', 'replace')}")

        if args.forge_ct is not None:
            fct = hx(args.forge_ct)
            faad = hx(args.forge_aad) if args.forge_aad else b""
            tag = ej0 ^ ghash(h, faad, fct)
            print(f"[+] forged tag: {tag:032x}")
    return 0


def main():
    ap = argparse.ArgumentParser(description="length extension и GCM nonce reuse")
    sub = ap.add_subparsers(dest="cmd", required=True)

    le = sub.add_parser("length-extend", help="удлинить хеш без ключа")
    le.add_argument("--alg", default="sha1", choices=sorted(ALGS))
    le.add_argument("--sig", required=True, help="известный digest (hex)")
    le.add_argument("--data", default="")
    le.add_argument("--data-hex", action="store_true")
    le.add_argument("--append", default="")
    le.add_argument("--append-hex", action="store_true")
    le.add_argument("--key-len", type=int, required=True)
    le.add_argument("--key-hex", help="только для самопроверки")
    le.add_argument("--out")
    le.set_defaults(func=cmd_length_extend)

    gc = sub.add_parser("gcm-nonce-reuse", help="два сообщения с одним nonce")
    gc.add_argument("--ct1", required=True)
    gc.add_argument("--tag1", required=True)
    gc.add_argument("--aad1", default="")
    gc.add_argument("--ct2", required=True)
    gc.add_argument("--tag2", required=True)
    gc.add_argument("--aad2", default="")
    gc.add_argument("--pt1", help="известный открытый текст первого")
    gc.add_argument("--pt1-hex", action="store_true")
    gc.add_argument("--ct3", default="", help="третий пакет для однозначного H")
    gc.add_argument("--tag3", default="")
    gc.add_argument("--aad3", default="")
    gc.add_argument("--forge-ct", help="подделать тег для этого ciphertext")
    gc.add_argument("--forge-aad", default="")
    gc.set_defaults(func=cmd_gcm)

    args = ap.parse_args()
    sys.exit(args.func(args) or 0)


if __name__ == "__main__":
    main()
