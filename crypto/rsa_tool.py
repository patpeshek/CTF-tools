#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
rsa_tool.py — атаки на учебный RSA: общий множитель, общий модуль, малая экспонента.

  # список модулей: строки "имя:n" (n — decimal или 0xhex)
  python rsa_tool.py shared --moduli moduli.txt --target target --e 65537 --cipher 0x1234

  # JSON вида {"keys":[{"name":"...","n":123}],"target":"...","wrapped":"0x..."}
  python rsa_tool.py shared --json registry.json --target target --cipher-field wrapped

  python rsa_tool.py shared --moduli moduli.txt --target target --e 65537 \
      --cipher 0x1234 --json-out key.bin

  python rsa_tool.py common-modulus --n ... --e1 3 --c1 ... --e2 65537 --c2 ...
  python rsa_tool.py small-e --n ... --e 3 --c ...
  python rsa_tool.py factor --n ... --p ...
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
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import common  # noqa: E402


def to_int(x) -> int:
    if isinstance(x, int):
        return x
    s = str(x).strip()
    if s.lower().startswith("0x"):
        return int(s, 16)
    return int(s)


def i2b(x: int) -> bytes:
    if x == 0:
        return b"\x00"
    n = (x.bit_length() + 7) // 8
    return x.to_bytes(n, "big")


def show(m: int):
    b = i2b(m)
    print("[+] int :", m)
    print("[+] hex :", b.hex())
    try:
        print("[+] text:", b.decode("utf-8"))
    except UnicodeDecodeError:
        print("[+] text: (не UTF-8)")


def load_moduli_file(path):
    out = []
    for line in open(path, encoding="utf-8", errors="replace"):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if ":" in line:
            name, val = line.split(":", 1)
        elif "=" in line:
            name, val = line.split("=", 1)
        else:
            name, val = f"key{len(out)}", line
        out.append((name.strip(), to_int(val)))
    return out


def load_json(path):
    data = json.load(open(path, encoding="utf-8"))
    keys = []

    def walk(obj):
        if isinstance(obj, dict):
            if "n" in obj and ("name" in obj or "id" in obj):
                keys.append((str(obj.get("name", obj.get("id"))), to_int(obj["n"])))
            for v in obj.values():
                walk(v)
        elif isinstance(obj, list):
            for v in obj:
                walk(v)

    walk(data)
    return keys, data


def find_field(data, name, field):
    """Ищет в JSON запись по name и берёт из неё field (например, wrapped)."""
    res = []

    def walk(obj):
        if isinstance(obj, dict):
            if str(obj.get("name", obj.get("id"))) == str(name):
                for k, v in obj.items():
                    if field in k.lower():
                        res.append(v)
            for v in obj.values():
                walk(v)
        elif isinstance(obj, list):
            for v in obj:
                walk(v)

    walk(data)
    return res[0] if res else None


def stream_variants(key: bytes, nonce_hex: str, ct_hex: str):
    """SHA256(key||nonce||counter) XOR — перебираем порядок/эндиан/counter."""
    try:
        nonce = bytes.fromhex(nonce_hex)
    except ValueError:
        nonce = str(nonce_hex).encode()
    try:
        ct = bytes.fromhex(ct_hex)
    except ValueError:
        return []
    out = []
    combos = []
    for endian in ("big", "little"):
        for csz in (4, 8):
            for order in ("knc", "kcn", "nkc", "nck", "cnk", "ckn"):
                combos.append((endian, csz, order))
    for endian, csz, order in combos:
        plain = bytearray()
        for i in range(0, len(ct), 32):
            ctr = (i // 32).to_bytes(csz, endian)
            parts = {"k": key, "n": nonce, "c": ctr}
            block = b"".join(parts[ch] for ch in order)
            ks = hashlib.sha256(block).digest()
            plain += bytes(a ^ b for a, b in zip(ct[i:i + 32], ks))
        text = bytes(plain)
        score = common.printable_ratio(text)
        flags = common.find_flags(text)
        if score > 0.85 or flags:
            out.append((score, endian, csz, order, text, flags))
    out.sort(key=lambda x: (-x[0], -len(x[5])))
    return out


def cmd_shared(args):
    keys, data = [], None
    if args.moduli:
        keys = load_moduli_file(args.moduli)
    if args.json:
        jkeys, data = load_json(args.json)
        keys += jkeys
    if not keys:
        print("[-] нет модулей")
        return

    target = None
    if args.target:
        for name, n in keys:
            if str(name) == str(args.target):
                target = (name, n)
        if not target:
            print(f"[-] нет ключа с именем {args.target!r}; есть: {[k[0] for k in keys][:20]}")
            return
    else:
        target = keys[0]
        print(f"[i] target не задан, беру первый: {target[0]}")

    e = args.e
    print(f"[+] target: {target[0]}  bits={target[1].bit_length()}")

    pairs = []
    for name, n in keys:
        if n == target[1]:
            continue
        g = math.gcd(target[1], n)
        if 1 < g < target[1]:
            pairs.append((name, g, n))
    if not pairs:
        print("[-] общих множителей не найдено")
        return
    for name, p, n in pairs:
        q = target[1] // p
        print(f"[+] общий множитель с {name}: p={p} ({p.bit_length()} bits)")

        phi = (p - 1) * (q - 1)
        try:
            d = pow(e, -1, phi)
        except ValueError:
            print("[!] e не взаимно прост с phi")
            continue
        print(f"[+] d = {d}")

        if args.cipher is not None:
            c = to_int(args.cipher)
        elif args.json and args.cipher_field and data is not None:
            raw = find_field(data, target[0], args.cipher_field)
            if raw is None and isinstance(data, dict):
                raw = data.get(args.cipher_field) or data.get("wrapped_session_key")
            if raw is None:
                print(f"[-] в JSON нет поля {args.cipher_field!r} у {target[0]}")
                return
            c = to_int(raw)
        else:
            print("[i] --cipher не задан, показываю только ключ")
            return

        m = pow(c, d, target[1])
        show(m)
        if args.json_out:
            open(args.json_out, "wb").write(i2b(m))
            print(f"[+] байты: {args.json_out}")

        # если в том же JSON есть nonce + ciphertext — сразу расшифруем поток
        if isinstance(data, dict) and data.get("ciphertext"):
            nonce = data.get("nonce") or data.get("iv") or ""
            key = i2b(m)
            got = stream_variants(key, str(nonce), str(data["ciphertext"]))
            if got:
                print("\n[+] поток SHA256(key||nonce||counter) XOR:")
                for score, endian, csz, order, text, flags in got[:3]:
                    print(f"    {endian}/{csz}/{order} printable={score:.2f}: {text[:200]!r}")
                    for f in flags:
                        print("    [!!!] ФЛАГ:", f)
            else:
                print("[-] поток не расшифровался ни одним вариантом порядка")
        return


def cmd_common(args):
    n, e1, e2 = to_int(args.n), args.e1, args.e2
    c1, c2 = to_int(args.c1), to_int(args.c2)
    g = math.gcd(e1, e2)
    if g != 1:
        print(f"[-] gcd(e1,e2)={g}, нужна другая атака")
        return
    a, b = 0, 0
    # расширенный Евклид: a*e1 + b*e2 = 1
    old_r, r = e1, e2
    old_s, s = 1, 0
    old_t, t = 0, 1
    while r:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
        old_t, t = t, old_t - q * t
    a, b = old_s, old_t
    # m = c1^a * c2^b mod n (с обратными при отрицательных)
    def pow_signed(c, exp):
        if exp >= 0:
            return pow(c, exp, n)
        return pow(pow(c, -1, n), -exp, n)

    m = (pow_signed(c1, a) * pow_signed(c2, b)) % n
    show(m)


def cmd_small_e(args):
    n, e, c = to_int(args.n), args.e, to_int(args.c)
    for k, m in enumerate(try_small_e(n, e, c, args.tries)):
        if k:
            print(f"[i] сработало c + {k}*n")
        show(m)
        return
    print(f"[-] точного корня нет за {args.tries} попыток: m^e > n или есть паддинг")


def cmd_factor(args):
    n, p = to_int(args.n), to_int(args.p)
    if n % p:
        print("[-] p не делит n")
        return
    q = n // p
    print(f"[+] p={p}\n[+] q={q}\n[+] n={p*q}")
    if args.e:
        d = pow(args.e, -1, (p - 1) * (q - 1))
        print(f"[+] d={d}")
        if args.cipher:
            show(pow(to_int(args.cipher), d, n))


def cmd_fermat(args):
    from math import isqrt
    n = to_int(args.n)
    a = isqrt(n)
    if a * a < n:
        a += 1
    for _ in range(args.max_iter):
        b2 = a * a - n
        b = isqrt(b2)
        if b * b == b2:
            p, q = a - b, a + b
            print(f"[+] p={p}\n[+] q={q}")
            if args.e:
                d = pow(args.e, -1, (p - 1) * (q - 1))
                print(f"[+] d={d}")
                if args.cipher:
                    show(pow(to_int(args.cipher), d, n))
            return
        a += 1
    print(f"[-] не нашёл за {args.max_iter} итераций (p и q не близки)")


def cmd_dp(args):
    """Факторизация по утечке dp/dq (d mod p-1) — идея из RsaCtfTool."""
    n, e = to_int(args.n), args.e
    for name, raw in (("dp", args.dp), ("dq", args.dq)):
        if not raw:
            continue
        f = factor_from_crt(n, e, to_int(raw))
        if not f:
            continue
        p, q = f, n // f
        print(f"[+] {name}: p={p}\n[+] q={q}")
        try:
            d = pow(e, -1, (p - 1) * (q - 1))
        except ValueError:
            print("[!] e не взаимно прост с phi")
            return
        print(f"[+] d={d}")
        if args.cipher:
            show(pow(to_int(args.cipher), d, n))
        return
    print("[-] dp/dq не подошли: это должна быть CRT-экспонента (d mod p-1), не d")
    print("    если дан полный d — расшифруй напрямую: pow(c, d, n)")


def cmd_batch(args):
    keys, _ = [], None
    if args.moduli:
        keys = load_moduli_file(args.moduli)
    if args.json:
        jkeys, _ = load_json(args.json)
        keys += jkeys
    if not keys:
        print("[-] нет модулей")
        return
    found = 0
    for i in range(len(keys)):
        for j in range(i + 1, len(keys)):
            n1, n2 = keys[i][1], keys[j][1]
            g = math.gcd(n1, n2)
            if 1 < g < min(n1, n2):
                found += 1
                print(f"[+] {keys[i][0]} <-> {keys[j][0]}: p={g} ({g.bit_length()} bits)")
    print(f"[+] общих множителей: {found} (из {len(keys)} ключей)")


def iroot(x: int, n: int) -> int:
    if x < 0:
        return -1
    if x in (0, 1):
        return x
    lo, hi = 0, 1 << ((x.bit_length() // n) + 2)
    while lo < hi:
        mid = (lo + hi) // 2
        if mid ** n < x:
            lo = mid + 1
        else:
            hi = mid
    return lo


def convergents(a: int, b: int):
    while b:
        q = a // b
        yield q
        a, b = b, a - q * b


def cmd_wiener(args):
    n, e = to_int(args.n), to_int(args.e)
    # цепная дробь e/n, подходящие дроби k/d
    num, den = e, n
    p_prev, p_cur = 0, 1
    q_prev, q_cur = 1, 0
    for q in convergents(num, den):
        p_prev, p_cur = p_cur, q * p_cur + p_prev
        q_prev, q_cur = q_cur, q * q_cur + q_prev
        k, d = p_cur, q_cur
        if k == 0 or (e * d - 1) % k:
            continue
        phi = (e * d - 1) // k
        s = n - phi + 1
        disc = s * s - 4 * n
        if disc < 0:
            continue
        r = iroot(disc, 2)
        if r * r != disc:
            continue
        p = (s + r) // 2
        q2 = (s - r) // 2
        if p * q2 == n:
            print(f"[+] d={d}")
            print(f"[+] p={p}\n[+] q={q2}")
            if args.cipher:
                m = pow(to_int(args.cipher), d, n)
                show(m)
            return
    print("[-] Wiener не сработал (d не маленькая или n/e не те)")


def cmd_broadcast(args):
    e = args.e
    pairs = []
    for p in args.pairs or []:
        for item in p.split(","):
            if ":" in item:
                n, c = item.split(":", 1)
                pairs.append((to_int(n), to_int(c)))
    if args.file:
        for line in open(args.file, encoding="utf-8", errors="replace"):
            if ":" in line:
                n, c = line.split(":", 1)
                try:
                    pairs.append((to_int(n), to_int(c)))
                except ValueError:
                    pass
    if len(pairs) < e:
        print(f"[-] нужно хотя бы {e} пар n:c")
        return
    N = 1
    for n, _ in pairs:
        N *= n
    x = 0
    for n, c in pairs:
        Mi = N // n
        x = (x + c * Mi * pow(Mi, -1, n)) % N
    m = iroot(x, e)
    if m ** e != x:
        print("[-] корень не целый (может, m^e > N или другая экспонента)")
        return
    show(m)


def isqrt(n: int) -> int:
    return math.isqrt(n)


# --- Franklin-Reiter: два сообщения связаны линейно, один модуль n ---

def _poly_trim(p):
    while len(p) > 1 and p[-1] == 0:
        p.pop()
    return p


def _poly_mul(a, b, n):
    out = [0] * (len(a) + len(b) - 1)
    for i, x in enumerate(a):
        if not x:
            continue
        for j, y in enumerate(b):
            out[i + j] = (out[i + j] + x * y) % n
    return out


def _poly_mod(a, b, n):
    """a mod b над Z_n. ValueError, если старший коэффициент b не обратим."""
    a = _poly_trim(a[:])
    inv = pow(b[-1], -1, n)
    while len(a) >= len(b) and not (len(a) == 1 and a[0] == 0):
        coef = a[-1] * inv % n
        shift = len(a) - len(b)
        for i, bc in enumerate(b):
            a[shift + i] = (a[shift + i] - coef * bc) % n
        _poly_trim(a)
    return a


def _poly_gcd(a, b, n):
    a, b = _poly_trim([x % n for x in a]), _poly_trim([x % n for x in b])
    while not (len(b) == 1 and b[0] == 0):
        a, b = b, _poly_mod(a, b, n)
    return a


def _poly_linear_pow(a, b, e, n):
    """(a*x + b)^e по модулю n; коэффициенты от младших к старшим."""
    result, base = [1], [b % n, a % n]
    while e:
        if e & 1:
            result = _poly_mul(result, base, n)
        e >>= 1
        if e:
            base = _poly_mul(base, base, n)
    return result


def franklin_reiter(n, e, c1, c2, a, b):
    """m1 из gcd(x^e - c1, (a*x + b)^e - c2). Возвращает (m, множитель n)."""
    f1 = [(-c1) % n] + [0] * (e - 1) + [1]
    f2 = _poly_linear_pow(a, b, e, n)
    f2[0] = (f2[0] - c2) % n
    g = _poly_gcd(f1, f2, n)
    if len(g) == 1:
        return None, None
    if len(g) == 2:
        return (-g[0] * pow(g[1], -1, n)) % n, None
    # старший коэффициент не обратим — заодно нашли множитель n
    factor = math.gcd(g[-1], n)
    return None, factor if 1 < factor < n else None


def cmd_related(args):
    e = args.e
    n = to_int(args.n)
    c1 = to_int(args.c1)
    c2 = to_int(args.c2)
    if e < 2:
        print("[-] e должно быть >= 2")
        return
    if e > 64:
        print(f"[-] e={e}: степень {e} — Franklin-Reiter не для таких экспонент;")
        print("    для большого e нужен coppersmith (малый корень) или короткий паддинг")
        return

    rels = []
    if args.rel:
        for item in args.rel.split(";"):
            item = item.strip()
            if not item:
                continue
            try:
                a_s, b_s = item.replace(",", " ").split()
                rels.append((to_int(a_s), to_int(b_s)))
            except ValueError:
                print(f"[-] не понял связь: {item!r} (нужно 'a,b')")
                return
    if args.auto or not rels:
        rels += [(1, 1), (1, -1), (1, 2), (1, 0), (2, 1), (1, 3), (3, 1)]

    for a, b in rels:
        try:
            m, factor = franklin_reiter(n, e, c1, c2, a, b)
        except ValueError:
            print(f"[i] a={a}, b={b}: старший коэффициент не обратим — пропускаю")
            continue
        if factor:
            print(f"[+] бонус: множитель n = {factor}")
            p, q = factor, n // factor
            m = pow(c1, pow(e, -1, (p - 1) * (q - 1)), n)
        if m is None:
            continue
        if pow(m, e, n) != c1 % n:
            print(f"[i] a={a}, b={b}: корень не подтвердился (m^e != c1)")
            continue
        print(f"[+] связь: m2 = {a}*m1 + {b}")
        show(m)
        for flag in common.find_flags(i2b(m)):
            print("[!!!] ФЛАГ:", flag)
        return

    print("[-] не сходится: ни одна связь не дала корень")
    print("[i] проверь, что c1 и c2 от одного n и связь действительно линейная")


def pollard_rho(n: int, rounds: int = 200_000):
    if n % 2 == 0:
        return 2
    import random
    for _ in range(3):
        c = random.randrange(1, n)
        x, y, d = 2, 2, 1
        for _ in range(rounds):
            x = (x * x + c) % n
            y = (y * y + c) % n
            y = (y * y + c) % n
            d = math.gcd(abs(x - y), n)
            if 1 < d < n:
                return d
    return None


def pollard_pm1(n: int, bound: int = 20_000):
    a = 2
    for j in range(2, bound):
        a = pow(a, j, n)
        if j % 64 == 0:
            d = math.gcd(a - 1, n)
            if 1 < d < n:
                return d
    d = math.gcd(a - 1, n)
    return d if 1 < d < n else None


SMALL_PRIMES = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)


def is_prime(n: int) -> bool:
    """Miller-Rabin: детерминирован для < 3e24, дальше — 12 баз (CTF-достаточно)."""
    if n < 2:
        return False
    for p in SMALL_PRIMES:
        if n % p == 0:
            return n == p
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for a in SMALL_PRIMES:
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def factor_small_prime(n: int, bound: int = 100_000):
    """q < bound: перебор малых простых (атака smallq из RsaCtfTool)."""
    if n % 2 == 0:
        return 2
    p = 3
    while p < bound:
        if n % p == 0:
            return p
        p += 2
    return None


def factor_from_crt(n: int, e: int, d_crt: int):
    """Утечка dp/dq: e*dp = 1 mod (p-1) => gcd(m^(e*dp)-m, n) = p."""
    for m in (2, 3, 5, 7, 11, 13, 17):
        g = math.gcd(pow(m, e * d_crt, n) - m, n)
        if 1 < g < n:
            return g
    return None


def perfect_power(n: int, max_k: int = 61):
    """n = p^k: возвращает (p, k), если p — простое и k простое/небольшое."""
    for k in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61):
        if k > max_k:
            break
        r = iroot(n, k)
        if r >= 2 and r ** k == n and is_prime(r):
            return r, k
    return None


def fermat_factor(n: int, limit: int = 300_000):
    if n % 2 == 0:
        return 2, n // 2
    a = isqrt(n)
    if a * a < n:
        a += 1
    for _ in range(limit):
        b2 = a * a - n
        b = isqrt(b2)
        if b * b == b2:
            return a - b, a + b
        a += 1
    return None


def try_small_e(n: int, e: int, c: int, tries: int = 2000):
    """c = m^e mod n; пробуем c + k*n как точный корень."""
    for k in range(tries):
        r = iroot(c + k * n, e)
        if r ** e == c + k * n:
            yield r


def decrypt_with(p: int, q: int, e: int, c: int):
    if p * q <= c:
        return None
    phi = (p - 1) * (q - 1)
    try:
        d = pow(e, -1, phi)
    except ValueError:
        return None
    return pow(c, d, p * q)


def parse_numbers(text: str):
    """[(метка, значение)] из произвольного текста: n = 123, c: 0x..., p=..."""
    pairs = []
    for line in text.splitlines():
        for m in re.finditer(r"([A-Za-z_]\w{0,20})\s*[:=]\s*(0x[0-9a-fA-F]+|\d+)", line):
            label = (m.group(1) or "").lower()
            pairs.append((label, to_int(m.group(2))))
        for m in re.finditer(r"(?<![0-9A-Za-z])(0x[0-9a-fA-F]{8,}|\d{12,})(?![0-9A-Za-z])", line):
            pairs.append(("", to_int(m.group(1))))
    # без меток — просто большие числа
    for m in re.finditer(r"\b\d{20,}\b", text):
        pairs.append(("", int(m.group(0))))
    seen, out = set(), []
    for label, val in pairs:
        key = (label, val)
        if key in seen:
            continue
        seen.add(key)
        out.append((label, val))
    return out


def cmd_auto(args):
    if args.file:
        raw_bytes = open(args.file, "rb").read()
        text = raw_bytes.decode("utf-8", "replace")
    elif args.text:
        raw_bytes = args.text.encode()
        text = args.text
    else:
        import sys as _sys
        raw_bytes = None
        text = _sys.stdin.read()

    key = None
    if raw_bytes is not None:
        try:
            from Crypto.PublicKey import RSA as _RSA
            key = _RSA.import_key(raw_bytes)
        except Exception:
            key = None
    if key is not None:
        print(f"[+] PEM/DER-ключ: {key.size_in_bits()} бит, e={key.e}"
              + (" (закрытый)" if key.has_private() else ""))

    pairs = parse_numbers(text)
    if not pairs and key is None and not args.cipher:
        print("[-] чисел не нашёл")
        return
    print(f"[+] чисел: {len(pairs)}")
    for label, val in pairs[:12]:
        print(f"    {label or '—':8s} {val if val < 10**12 else str(val)[:20] + '…'} ({val.bit_length()} бит)")

    big = sorted({v for _, v in pairs if v > 2**32}, reverse=True)
    small = {v for _, v in pairs if v in (3, 5, 7, 11, 17, 257, 65537)}
    labeled = {}
    for label, val in pairs:
        if label:
            labeled.setdefault(label, val)

    e = labeled.get("e") or labeled.get("exp") or labeled.get("exponent")
    if not e:
        e = max(small) if small else 65537
    e = e if e < 2**32 else 65537

    n = labeled.get("n") or labeled.get("modulus") or labeled.get("mod")
    cs = [labeled[k] for k in ("c", "cipher", "ct", "ciphertext") if k in labeled]
    if key is not None:
        n, e = key.n, key.e
    if args.cipher:
        cval = args.cipher
        if os.path.exists(cval):
            blob = open(cval, "rb").read()
            try:
                cs = [int(blob.decode().strip(), 0)]
            except Exception:
                cs = [int.from_bytes(blob, "big")]
        else:
            cs = [to_int(cval)]
    if not n:
        cand = [v for v in big if v > e]
        if cand:
            n = cand[0]
    if not cs:
        cs = [v for v in big if n and v < n][:3]

    print(f"[+] гипотеза: e={e}, n={n and str(n)[:24] + '…' if n else '?'}, c-кандидатов={len(cs)}")
    results = []

    def emit(m, how):
        if not m or m <= 0:
            return
        b = i2b(m)
        results.append((how, m, b))

    # 1. сами числа как текст
    for v in big[:6]:
        b = i2b(v)
        if all(32 <= x < 127 or x in (9, 10, 13) for x in b) and len(b) >= 4:
            emit(v, "число как bytes")

    # 2. малая экспонента
    if n:
        for c in cs or []:
            if c < n:
                for k, m in enumerate(try_small_e(n, e, c, args.tries)):
                    emit(m, f"small-e (k={k})")
                    break

    # 3. общий делитель между n и другими большими числами
    for i in range(len(big)):
        for j in range(i + 1, len(big)):
            g = math.gcd(big[i], big[j])
            if 1 < g < min(big[i], big[j]):
                p, q = g, big[i] // g
                if p * q == big[i]:
                    print(f"[+] gcd-факторизация: {big[i].bit_length()} бит")
                    for c in cs:
                        emit(decrypt_with(p, q, e, c), "gcd -> decrypt")

    # 3b. готовый d или утечка dp/dq
    d_given = labeled.get("d") or labeled.get("priv") or labeled.get("private")
    if d_given is None and key is not None and key.has_private():
        d_given = key.d
    if n and d_given:
        print("[+] задан закрытый показатель d")
        for c in cs:
            emit(pow(c, d_given, n), "d -> decrypt")
    for key in ("dp", "dq", "d_crt", "crt_dp", "crt_dq"):
        dv = labeled.get(key)
        if not (n and dv):
            continue
        f = factor_from_crt(n, e, dv)
        if f:
            print(f"[+] утечка {key}: n факторизован")
            for c in cs:
                emit(decrypt_with(f, n // f, e, c), f"{key} -> decrypt")
            break

    # 3c. e=1, простое n, n=p^k
    if n and e == 1:
        for c in cs:
            emit(c, "e=1: c и есть m")
    if n:
        if is_prime(n):
            try:
                d = pow(e, -1, n - 1)
                print("[+] n простое: phi = n-1")
                for c in cs:
                    emit(pow(c, d, n), "n prime -> decrypt")
            except ValueError:
                pass
        else:
            pp = perfect_power(n)
            if pp:
                r, k = pp
                print(f"[+] n = {str(r)[:16]}…^{k}")
                try:
                    d = pow(e, -1, (r - 1) * r ** (k - 1))
                    for c in cs:
                        emit(pow(c, d, n), f"n=p^{k} -> decrypt")
                except ValueError:
                    pass

    # 3d. маленький простой множитель (smallq)
    if n:
        sp = factor_small_prime(n)
        if sp and sp < n:
            print(f"[+] малый простой множитель: {sp}")
            for c in cs:
                emit(decrypt_with(sp, n // sp, e, c), "smallq -> decrypt")

    # 4. факторизация n
    if n and n.bit_length() <= 256:
        f = None
        import time as _t
        t0 = _t.time()
        f = fermat_factor(n, args.fermat)
        how = "Ферма"
        if not f:
            p = pollard_pm1(n)
            if p:
                f, how = (p, n // p), "p-1"
        if not f:
            p = pollard_rho(n, args.rho)
            if p:
                f, how = (p, n // p), "rho"
        if f:
            print(f"[+] факторизация ({how}): {f[0].bit_length()}/{f[1].bit_length()} бит")
            for c in cs:
                emit(decrypt_with(f[0], f[1], e, c), f"{how} -> decrypt")

    # 5. Винера (малый d)
    if n and labeled.get("e"):
        try:
            for k, d, _ in convergents(e, n):
                if k == 0:
                    continue
                if (e * d - 1) % k:
                    continue
                phi = (e * d - 1) // k
                s = n - phi + 1
                disc = s * s - 4 * n
                if disc < 0:
                    continue
                r = isqrt(disc)
                if r * r == disc:
                    p, q = (s + r) // 2, (s - r) // 2
                    if p * q == n:
                        print(f"[+] Винер: d={d}")
                        for c in cs:
                            emit(decrypt_with(p, q, e, c), "Wiener -> decrypt")
                        break
        except Exception:
            pass

    # 6. если p/q даны явно
    p, q = labeled.get("p"), labeled.get("q")
    if p and q:
        print("[+] p и q заданы")
        for c in cs:
            emit(decrypt_with(p, q, e, c), "p,q -> decrypt")

    # вывод
    best = []
    seen = set()
    for how, m, b in results:
        if b in seen:
            continue
        seen.add(b)
        text_ok = sum(32 <= x < 127 or x in (9, 10, 13) for x in b) / max(1, len(b))
        best.append((text_ok, how, m, b))
    best.sort(reverse=True)
    if not best:
        print("[-] ни одна атака не дала осмысленного результата")
        print("    проверь: e маленькое? p,q рядом? n общий с другим? d маленькое?")
        if n and n.bit_length() >= 256 and e >= 65537:
            print("    n большой и слабостей не видно: это может быть Coppersmith/"
                  "решётки (частичное p, малый корень) — нужен Sage, тут не решаем")
        return
    for ok, how, m, b in best[:8]:
        try:
            s = b.decode("utf-8")
        except UnicodeDecodeError:
            s = b.decode("latin-1")
        print(f"\n[+] {how}: {s[:300]!r}")
        print(f"    hex: {b.hex()[:120]}")
        for f in common.find_flags(b):
            print("[!!!] ФЛАГ:", f)


# ---------------------------------------------------------------- решётки


def _nearest(a: int, b: int) -> int:
    if a >= 0:
        return (2 * a + b) // (2 * b)
    return -((-2 * a + b) // (2 * b))


def _lll_init(B):
    n = len(B)
    m = len(B[0])
    G = [[sum(B[i][k] * B[j][k] for k in range(m)) for j in range(n)]
         for i in range(n)]
    d = [0] * (n + 1)
    d[0] = 1
    lam = [[0] * n for _ in range(n)]
    for i in range(n):
        for j in range(i + 1):
            u = G[i][j]
            for k in range(j):
                num = d[k + 1] * u - lam[i][k] * lam[j][k]
                if num % d[k]:
                    raise ArithmeticError("LLL: неточное деление")
                u = num // d[k]
            if j < i:
                lam[i][j] = u
            else:
                d[i + 1] = u
                if u == 0:
                    raise ValueError("LLL: векторы линейно зависимы")
    return d, lam


def lll(B, delta=(3, 4)):
    """LLL с инкрементальными обновлениями (Cohen 2.6.3), без GS-пересчёта."""
    B = [[int(x) for x in row] for row in B]
    n = len(B)
    if n <= 1:
        return B
    d, lam = _lll_init(B)
    dn, dd = delta
    k = 1
    while k < n:
        for j in range(k - 1, -1, -1):
            if 2 * abs(lam[k][j]) > d[j + 1]:
                q = _nearest(lam[k][j], d[j + 1])
                B[k] = [B[k][i] - q * B[j][i] for i in range(len(B[k]))]
                lam[k][j] -= q * d[j + 1]
                for i in range(j):
                    lam[k][i] -= q * lam[j][i]
        if dd * d[k + 1] * d[k - 1] >= (dn * d[k] * d[k]
                                        - dd * lam[k][k - 1] ** 2):
            k += 1
        else:
            B[k], B[k - 1] = B[k - 1], B[k]
            for j in range(k - 2, -1, -1):
                lam[k][j], lam[k - 1][j] = lam[k - 1][j], lam[k][j]
            l = lam[k][k - 1]
            Bk = (d[k - 1] * d[k + 1] + l * l) // d[k]
            for i in range(k + 1, n):
                t = lam[i][k]
                lam[i][k] = (d[k + 1] * lam[i][k - 1] - l * t) // d[k]
                lam[i][k - 1] = (Bk * t + l * lam[i][k]) // d[k + 1]
            d[k] = Bk
            k = max(k - 1, 1)
    return B


def _pmul(a, b):
    out = [0] * (len(a) + len(b) - 1)
    for i, x in enumerate(a):
        if x:
            for j, y in enumerate(b):
                if y:
                    out[i + j] += x * y
    return out


def _ppow(a, k):
    r = [1]
    base = a
    while k:
        if k & 1:
            r = _pmul(r, base)
        base = _pmul(base, base)
        k >>= 1
    return r


def _vector_roots(rows, X):
    """Корни из коротких векторов: общий делитель пар полиномов, затем корни."""
    from sympy import Poly, Symbol, gcd as sym_gcd
    x = Symbol("x")
    polys = []
    for row in rows:
        coef = [row[j] // pow(X, j) for j in range(len(row))]
        while len(coef) > 1 and coef[-1] == 0:
            coef.pop()
        if len(coef) <= 1:
            continue
        polys.append(Poly(sum(c * x ** i for i, c in enumerate(coef)), x))
    roots = set()
    for i in range(len(polys)):
        for j in range(i + 1, len(polys)):
            try:
                g = sym_gcd(polys[i], polys[j])
            except Exception:
                continue
            if 1 <= g.degree() <= 4:
                for r in g.ground_roots():
                    if getattr(r, "is_Integer", False):
                        roots.add(int(r))
    return roots


def coppersmith(f, N: int, X: int, beta=1.0, m=None, t=None):
    """Малые корни f(x) ≡ 0 mod N (beta=1) или mod p | N (beta<1)."""
    f = [int(c) for c in f]
    while len(f) > 1 and f[-1] == 0:
        f.pop()
    d = len(f) - 1
    if m is None:
        m = 3 if beta >= 1 else 5
    if t is None:
        t = 0 if beta >= 1 else m
    polys = []
    for i in range(m):
        base = _ppow(f, i)
        coef = [c * pow(N, m - i) for c in base]
        for j in range(d):
            polys.append([0] * j + coef)
    fm = _ppow(f, m)
    for i in range(t):
        polys.append([0] * i + fm)
    dim = d * m + t
    B = []
    for p in polys:
        row = [0] * dim
        for j, c in enumerate(p):
            if j < dim:
                row[j] = c * pow(X, j)
        B.append(row)
    return sorted(x for x in _vector_roots(lll(B), X) if 0 <= x < X)


def cmd_coppersmith(args):
    N, e, c = to_int(args.n), args.e, to_int(args.c)
    hi = to_int(args.known_high) if args.known_high else 0
    A = hi << args.unknown_bits
    X = 1 << args.unknown_bits
    f = [math.comb(e, k) * A ** (e - k) for k in range(e + 1)]
    f[0] -= c
    print(f"[i] e={e}, известно {A.bit_length()} бит, неизвестно {args.unknown_bits}")
    roots = coppersmith(f, N, X, beta=1, m=args.m)
    hit = None
    for r in roots:
        if pow(A + r, e, N) == c % N:
            hit = A + r
            break
    if hit is None:
        print("[-] корень не найден (увеличь --m или проверь границы)")
        return 1
    show(hit)
    return 0


def cmd_partial_p(args):
    N = to_int(args.n)
    bits = args.unknown_bits
    ph = to_int(args.p_high)
    roots = coppersmith([ph << bits, 1], N, 1 << bits,
                        beta=0.5, m=args.m, t=args.t)
    print(f"[i] известно {ph.bit_length()} бит p, неизвестно {bits}")
    for r in roots:
        p = (ph << bits) | r
        if p > 1 and N % p == 0:
            q = N // p
            print(f"[+] p = {p}")
            print(f"[+] q = {q}")
            if args.e and args.cipher:
                d = pow(args.e, -1, (p - 1) * (q - 1))
                show(pow(to_int(args.cipher), d, N))
            return 0
    print("[-] p не восстановился")
    return 1


def cmd_lsb_oracle(args):
    N, e = to_int(args.n), args.e
    c0 = to_int(args.c)
    c = c0
    if args.bits:
        bits = [int(b) for b in re.split(r"[,\s]+", args.bits.strip()) if b]
    elif args.oracle_cmd:
        bits = []
        for _ in range(N.bit_length()):
            c = c * pow(2, e, N) % N
            r = subprocess.run(args.oracle_cmd, shell=True, input=str(c),
                               capture_output=True, text=True, timeout=30)
            out = (r.stdout or "").strip()
            if not out:
                print(f"[-] оракул ничего не ответил (rc={r.returncode})")
                return 1
            bits.append(1 if out[0] == "1" else 0)
        c = c0
    else:
        print("[-] нужен --bits или --oracle-cmd")
        return 1

    lower, upper = 0, N
    for bit in bits:
        c = c * pow(2, e, N) % N
        mid = (lower + upper) // 2
        if bit:
            lower = mid
        else:
            upper = mid
    m = upper
    # округление на каждом шаге даёт дрейф вниз; добираем точным перебором
    if pow(m, e, N) != c0 % N:
        lo = max(0, upper - 65536)
        hi = min(N, upper + 65537)
        for cand in range(lo, hi):
            if pow(cand, e, N) == c0 % N:
                m = cand
                break
    show(m)
    if pow(m, e, N) == c0 % N:
        print("[+] проверка: m^e mod n совпал")
    else:
        print("[!] m^e mod n не совпал — битов мало или они неверные")
    return 0


def _bf_attempt(N, e, m, t, delta, top=10):
    from sympy import Poly, expand, resultant, symbols
    x, y = symbols("x y")
    A = N + 1
    f = 1 + x * (A + y)
    X = int(2 * N ** delta)
    Y = 2 * isqrt(N)
    polys = []
    for k in range(m + 1):
        fk = expand(f ** k)
        for i in range(m - k + 1):
            polys.append(expand(x ** i * fk * e ** (m - k)))
    for k in range(m + 1):
        fk = expand(f ** k)
        for j in range(1, t + 1):
            polys.append(expand(y ** j * fk * e ** (m - k)))

    mons = set()
    for p in polys:
        mons |= set(p.as_poly(x, y).monoms())
    mons = sorted(mons, key=lambda mt: (sum(mt), mt))
    B = []
    for p in polys:
        row = [0] * len(mons)
        pd = p.as_poly(x, y)
        for mon, coef in zip(pd.monoms(), pd.coeffs()):
            row[mons.index(mon)] = int(coef) * X ** mon[0] * Y ** mon[1]
        B.append(row)

    R = lll(B)
    cands = []
    for row in R[:top]:
        poly = 0
        for coef, (i, j) in zip(row, mons):
            if coef:
                poly += (coef // (X ** i * Y ** j)) * x ** i * y ** j
        cands.append(poly)

    for a in range(len(cands)):
        for b in range(a + 1, len(cands)):
            res = resultant(cands[a], cands[b], x)
            if res == 0:
                continue
            try:
                pr = Poly(res, y)
            except Exception:
                continue
            if pr.degree() > 10:
                continue
            for root in pr.ground_roots():
                if not getattr(root, "is_Integer", False):
                    continue
                y0 = int(root)
                try:
                    kk = (-pow(A + y0, -1, e)) % e
                except ValueError:
                    continue
                num = 1 + kk * (A + y0)
                if num % e:
                    continue
                d = num // e
                if d > 0 and pow(2, e * d, N) == 2:
                    return d, kk, y0
    return None


def cmd_boneh_durfee(args):
    N, e = to_int(args.n), to_int(args.e)
    if args.m is not None:
        grid = [(args.m, args.t or 2, args.delta or 0.28)]
    else:
        grid = [(3, 1, 0.27), (4, 2, 0.27), (4, 2, 0.26),
                (5, 2, 0.27), (5, 3, 0.28)]
    for m, t, delta in grid:
        print(f"[i] попытка m={m}, t={t}, delta={delta}")
        try:
            res = _bf_attempt(N, e, m, t, delta)
        except ValueError as exc:
            print(f"[!] {exc}")
            continue
        if res:
            d, kk, y0 = res
            print(f"[+] d = {d}")
            print(f"[+] k = {kk}, p+q = {-y0}")
            if args.cipher:
                show(pow(to_int(args.cipher), d, N))
            return 0
    print("[-] не нашлось — увеличь --delta или задай --m/--t вручную")
    return 1


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("shared", help="общий простой множитель у двух n")
    s.add_argument("--moduli")
    s.add_argument("--json")
    s.add_argument("--target")
    s.add_argument("--e", type=int, default=65537)
    s.add_argument("--cipher")
    s.add_argument("--cipher-field", default="wrapped")
    s.add_argument("--json-out")
    s.set_defaults(func=cmd_shared)

    c = sub.add_parser("common-modulus", help="одинаковый n, разные e")
    c.add_argument("--n", required=True)
    c.add_argument("--e1", type=int, required=True)
    c.add_argument("--c1", required=True)
    c.add_argument("--e2", type=int, required=True)
    c.add_argument("--c2", required=True)
    c.set_defaults(func=cmd_common)

    se = sub.add_parser("small-e", help="m^e < n, целочисленный корень")
    se.add_argument("--n", required=True)
    se.add_argument("--e", type=int, required=True)
    se.add_argument("--c", required=True)
    se.add_argument("--tries", type=int, default=2000)
    se.set_defaults(func=cmd_small_e)

    f = sub.add_parser("factor", help="известен p")
    f.add_argument("--n", required=True)
    f.add_argument("--p", required=True)
    f.add_argument("--e", type=int)
    f.add_argument("--cipher")
    f.set_defaults(func=cmd_factor)

    fe = sub.add_parser("fermat", help="p и q близки: факторизация Ферма")
    fe.add_argument("--n", required=True)
    fe.add_argument("--max-iter", type=int, default=2_000_000)
    fe.add_argument("--e", type=int)
    fe.add_argument("--cipher")
    fe.set_defaults(func=cmd_fermat)

    dl = sub.add_parser("dp-leak", help="утечка dp/dq (d mod p-1): факторизация n")
    dl.add_argument("--n", required=True)
    dl.add_argument("--e", type=int, default=65537)
    dl.add_argument("--dp")
    dl.add_argument("--dq")
    dl.add_argument("--cipher")
    dl.set_defaults(func=cmd_dp)

    ba = sub.add_parser("batch", help="все пары модулей с общим множителем")
    ba.add_argument("--moduli")
    ba.add_argument("--json")
    ba.set_defaults(func=cmd_batch)

    wi = sub.add_parser("wiener", help="малая закрытая экспонента d")
    wi.add_argument("--n", required=True)
    wi.add_argument("--e", required=True)
    wi.add_argument("--cipher")
    wi.set_defaults(func=cmd_wiener)

    br = sub.add_parser("broadcast", help="Hastad: одно e, несколько n/c")
    br.add_argument("--e", type=int, required=True)
    br.add_argument("--pairs", action="append", default=[],
                    help='строки "n:c", можно несколько через запятую')
    br.add_argument("--file", help="файл со строками n:c")
    br.set_defaults(func=cmd_broadcast)

    rl = sub.add_parser("related", help="Franklin-Reiter: m2 = a*m1 + b при одном n")
    rl.add_argument("--n", required=True)
    rl.add_argument("--e", type=int, required=True)
    rl.add_argument("--c1", required=True)
    rl.add_argument("--c2", required=True)
    rl.add_argument("--rel", help='связь "a,b" (несколько — через ";")')
    rl.add_argument("--auto", action="store_true", help="перебрать типовые связи")
    rl.set_defaults(func=cmd_related)

    cp = sub.add_parser("coppersmith", help="Coppersmith: частично известный m")
    cp.add_argument("--n", required=True)
    cp.add_argument("--e", type=int, required=True)
    cp.add_argument("--c", required=True)
    cp.add_argument("--known-high", default="", help="известные старшие биты m")
    cp.add_argument("--unknown-bits", type=int, required=True)
    cp.add_argument("--m", type=int, default=3)
    cp.set_defaults(func=cmd_coppersmith)

    pp = sub.add_parser("partial-p", help="Coppersmith: часть p известна")
    pp.add_argument("--n", required=True)
    pp.add_argument("--p-high", required=True, help="p >> unknown_bits")
    pp.add_argument("--unknown-bits", type=int, required=True)
    pp.add_argument("--m", type=int, default=5)
    pp.add_argument("--t", type=int, default=5)
    pp.add_argument("--e", type=int)
    pp.add_argument("--cipher")
    pp.set_defaults(func=cmd_partial_p)

    lo = sub.add_parser("lsb-oracle", help="оракул младшего бита")
    lo.add_argument("--n", required=True)
    lo.add_argument("--e", type=int, default=65537)
    lo.add_argument("--c", required=True)
    lo.add_argument("--bits", help="готовые биты через запятую")
    lo.add_argument("--oracle-cmd", help="команда: ciphertext в stdin, 0/1 в stdout")
    lo.set_defaults(func=cmd_lsb_oracle)

    bd = sub.add_parser("boneh-durfee", help="малая d (до N^0.292)")
    bd.add_argument("--n", required=True)
    bd.add_argument("--e", required=True)
    bd.add_argument("--m", type=int, default=None)
    bd.add_argument("--t", type=int, default=None)
    bd.add_argument("--delta", type=float, default=None)
    bd.add_argument("--cipher")
    bd.set_defaults(func=cmd_boneh_durfee)

    au = sub.add_parser("auto", help="числа из любого текста -> все атаки подряд")
    au.add_argument("file", nargs="?", help="файл с числами (или --text)")
    au.add_argument("--file", dest="file_opt")
    au.add_argument("--text")
    au.add_argument("--tries", type=int, default=2000, help="попыток small-e")
    au.add_argument("--cipher", help="шифротекст: число, hex или файл с ним")
    au.add_argument("--fermat", type=int, default=200_000)
    au.add_argument("--rho", type=int, default=100_000)
    au.set_defaults(func=cmd_auto)

    args = ap.parse_args()
    if getattr(args, "file", None):
        args.file = args.file
    elif getattr(args, "file_opt", None):
        args.file = args.file_opt
    for attr in ("file", "json", "moduli"):
        path = getattr(args, attr, None)
        if isinstance(path, str) and path and not os.path.exists(path):
            print(f"[-] нет файла: {path}")
            return
    args.func(args)


if __name__ == "__main__":
    main()
