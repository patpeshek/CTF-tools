"""ecc.py — атаки на эллиптические кривые из CTF.

Главное правило этого файла: **лучше вернуть «не вышло», чем неверный d**.
Поэтому каждый найденный логарифм проверяется подстановкой (d*G == Q), точки
проверяются на принадлежность кривой, а p — на простоту. Молчаливый неверный
ответ в CTF хуже отсутствия ответа: с ним ищешь ошибку не там.

Что умеет:
  * разбор параметров из текста задачи (в т.ч. `2^255-19`, `0x…`, `1_000_003`,
    `EllipticCurve(GF(p), [a, b])`, точки со скобками и без);
  * **BSGS** — дискретный логарифм в подгруппе разумного размера;
  * **Полиг–Хеллман** — когда порядок гладкий (самый частый CTF-случай);
  * **сингулярная кривая** (дискриминант 0) — определяет касп/узел через
    кратный корень, без перебора по всему полю;
  * честные отказы: не на кривой, составное p, `n` не кратно порядку,
    аномальная кривая (нужна атака Смарта — её здесь нет).

  python crypto/ecc.py --file task.txt
  python crypto/ecc.py --p 9739 --a 497 --b 1768 --gx 1801 --gy 5361 \
      --qx 4726 --qy 6287
"""
from __future__ import annotations

import argparse
import re
import sys

NUM = r"(-?\d+)"


# ---------------------------------------------------------------- поле -------
def gcd(a: int, b: int) -> int:
    while b:
        a, b = b, a % b
    return abs(a)


def is_prime(n: int) -> bool:
    """Миллер–Рабин: детерминированные базы для 64 бит, случайные выше."""
    if n < 2:
        return False
    for q in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % q == 0:
            return n == q
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    bases = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]
    if n.bit_length() > 64:
        bases = bases + [n - 2]
    for a in bases:
        if a % n == 0:
            continue
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


def inv(x: int, p: int) -> int:
    x %= p
    if x == 0:
        raise ZeroDivisionError("0 не имеет обратного")
    if gcd(x, p) != 1:
        raise ZeroDivisionError(f"{x} и {p} не взаимно просты (p составное?)")
    return pow(x, -1, p)


# ---------------------------------------------------------------- группа -----
def add(P, Q, a, p):
    if P is None:
        return Q
    if Q is None:
        return P
    x1, y1 = P
    x2, y2 = Q
    if x1 == x2 and (y1 + y2) % p == 0:
        return None
    if P == Q:
        if y1 % p == 0:
            return None
        lam = (3 * x1 * x1 + a) * inv(2 * y1, p) % p
    else:
        lam = (y2 - y1) * inv(x2 - x1, p) % p
    x3 = (lam * lam - x1 - x2) % p
    return x3, (lam * (x1 - x3) - y1) % p


def mul(k: int, P, a, p):
    """k*P. Отрицательный k считается честно через -P."""
    if P is None:
        return None
    if k < 0:
        return mul(-k, (P[0], (-P[1]) % p), a, p)
    R = None
    while k > 0:
        if k & 1:
            R = add(R, P, a, p)
        P = add(P, P, a, p)
        k >>= 1
    return R


def on_curve(P, a, b, p) -> bool:
    if P is None:
        return True
    x, y = P
    return (y * y - (x * x * x + a * x + b)) % p == 0


# ---------------------------------------------------------------- атаки ------
def bsgs(P, Q, order: int, a, p, limit: int = 1 << 34):
    """Q = k*P в подгруппе порядка order. Результат проверяется подстановкой."""
    if order is None or order < 1:
        return None
    if Q is None:
        return 0
    if order > limit:
        return None
    m = int(order ** 0.5) + 1
    table = {}
    cur = None
    for j in range(m):
        table.setdefault(cur, j)
        cur = add(cur, P, a, p)
    step = mul(m, P, a, p)
    neg = None if step is None else (step[0], (-step[1]) % p)
    cur = Q
    for i in range(m + 1):
        if cur in table:
            k = (i * m + table[cur]) % order
            if mul(k, P, a, p) == Q:
                return k
            return None
        cur = add(cur, neg, a, p) if neg else None
    return None


def factorize(n: int, limit: int = 1_000_000) -> dict:
    """Пробное деление + Поллард-ро. Не выдаёт составное за простое."""
    out: dict[int, int] = {}
    d = 2
    while d * d <= n and d <= limit:
        while n % d == 0:
            out[d] = out.get(d, 0) + 1
            n //= d
        d += 1 if d == 2 else 2
    if n > 1:
        if is_prime(n):
            out[n] = out.get(n, 0) + 1
        else:
            # не разложили: помечаем как составное, а не «простое»
            out[n] = out.get(n, 0) + 1
    return out


def _crt(residues, moduli):
    M = 1
    for m in moduli:
        M *= m
    total = 0
    for r, m in zip(residues, moduli):
        Mi = M // m
        total = (total + r * Mi * inv(Mi, m)) % M
    return total


def pohlig_hellman(P, Q, order: int, a, p, limit: int = 1 << 34):
    """DLP по кускам; результат обязателен к проверке (делается здесь)."""
    if order is None or order < 1 or Q is None:
        return (0 if Q is None else None), {}
    fac = factorize(order)
    residues, moduli = [], []
    for q, e in fac.items():
        qe = q ** e
        if not is_prime(q) or qe > limit:
            return None, fac
        Pi = mul(order // qe, P, a, p)
        Qi = mul(order // qe, Q, a, p)
        di = bsgs(Pi, Qi, qe, a, p)
        if di is None:
            return None, fac
        residues.append(di % qe)
        moduli.append(qe)
    if not residues:
        return None, fac
    total = _crt(residues, moduli) % order
    if mul(total, P, a, p) != Q:      # <-- главная проверка
        return None, fac
    return total, fac


def sqrt_mod(n: int, p: int):
    """Квадратный корень по модулю простого p (Тонелли–Шенкс)."""
    n %= p
    if n == 0:
        return 0
    if pow(n, (p - 1) // 2, p) != 1:
        return None
    if p % 4 == 3:
        return pow(n, (p + 1) // 4, p)
    q, s = p - 1, 0
    while q % 2 == 0:
        q //= 2
        s += 1
    z = 2
    while pow(z, (p - 1) // 2, p) != p - 1:
        z += 1
    m, c, t, r = s, pow(z, q, p), pow(n, q, p), pow(n, (q + 1) // 2, p)
    while t != 1:
        i, t2 = 0, t
        while t2 != 1:
            t2 = t2 * t2 % p
            i += 1
            if i == m:
                return None
        b = pow(c, 1 << (m - i - 1), p)
        m, c = i, b * b % p
        t = t * c % p
        r = r * b % p
    return r


def singular_attack(a: int, b: int, p: int):
    """Дискриминант 0: находим кратный корень, отличаем касп от узла.

    Касп (y^2 = x^3) даёт аддитивную группу, узел — мультипликативную
    F_p^*; для атаки это разные редукции, поэтому тип важен.
    """
    if (4 * a ** 3 + 27 * b ** 2) % p != 0:
        return None
    try:
        # кратный корень: 3x^2 + a = 0  →  x^2 = -a/3
        rhs = (-a * inv(3, p)) % p if a % p else 0
        x0 = sqrt_mod(rhs, p) if rhs else 0
        if x0 is None:
            return {"type": "singular", "x0": None,
                    "hint": "кривая сингулярна; кратный корень не нашёлся"}
        if (x0 ** 3 + a * x0 + b) % p != 0:
            return {"type": "singular", "x0": None, "hint": "кривая сингулярна"}
    except ZeroDivisionError:
        return {"type": "singular", "x0": None, "hint": "кривая сингулярна"}
    # у каспа вторая производная 6x0 == 0, у узла — нет
    kind = "cusp" if (6 * x0) % p == 0 else "node"
    return {"type": kind, "x0": x0,
            "hint": ("касп: группа изоморфна аддитивной (DLP тривиален)" if kind == "cusp"
                     else "узел: группа изоморфна мультипликативной F_p^*")}


# ---------------------------------------------------------------- разбор -----
def _num(token: str) -> int:
    token = token.strip().replace("_", "")
    m = re.fullmatch(r"(-?\d+)", token)
    if m:
        return int(m.group(1))
    m = re.fullmatch(r"0x([0-9a-fA-F]+)", token)
    if m:
        return int(m.group(1), 16)
    m = re.fullmatch(r"(-?\d+)\s*\^\s*(\d+)\s*([+-])\s*(\d+)", token)
    if m:
        base, exp, sign, off = int(m.group(1)), int(m.group(2)), m.group(3), int(m.group(4))
        return base ** exp + (off if sign == "+" else -off)
    return None


def parse_text(text: str) -> dict:
    out = {}
    # p может быть и hex, и 2^n - c
    m = re.search(r"(?im)^\s*p\s*=\s*([0-9a-fx_]+(?:\s*\^\s*\d+)?(?:\s*[+-]\s*\d+)?)", text)
    if m:
        val = _num(m.group(1))
        if val is not None:
            out["p"] = val
    for key, pat in (("a", r"(?im)^\s*a\s*=\s*(-?\d+)"),
                     ("b", r"(?im)^\s*b\s*=\s*(-?\d+)"),
                     ("n", r"(?im)^\s*(?:n|order)\s*=\s*(-?\d+)")):
        m = re.search(pat, text)
        if m:
            out[key] = int(m.group(1))
    m = re.search(r"EllipticCurve\(\s*GF\(\s*([0-9a-fx_]+)\s*\)\s*,\s*\[\s*"
                  r"(-?\d+)\s*,\s*(-?\d+)\s*\]\s*\)", text)
    if m:
        pv = _num(m.group(1))
        if pv:
            out.setdefault("p", pv)
        out.setdefault("a", int(m.group(2)))
        out.setdefault("b", int(m.group(3)))
    m = re.search(r"(?i)\bG\s*=\s*E?\(?\s*(-?\d+)\s*,\s*(-?\d+)\s*\)?", text)
    if m:
        out["G"] = (int(m.group(1)), int(m.group(2)))
    m = re.search(r"(?i)\bQ\s*=\s*E?\(?\s*(-?\d+)\s*,\s*(-?\d+)\s*\)?", text)
    if m:
        out["Q"] = (int(m.group(1)), int(m.group(2)))
    return out


# ---------------------------------------------------------------- решение ----
def solve(params, verbose=True, force=False):
    say = print if verbose else (lambda *a, **k: None)
    p, a, b = params.get("p"), params.get("a"), params.get("b")
    G, Q = params.get("G"), params.get("Q")
    if not p or a is None or b is None or G is None or Q is None:
        say("[-] нужны p, a, b, G=(x,y) и Q=(x,y)")
        return None

    say(f"[+] кривая: y^2 = x^3 + {a}x + {b} mod {p}")
    say(f"    G={G}  Q={Q}")
    if not is_prime(p):
        say("[!] p не простое — арифметика поля не работает, дальше нет смысла")
        return None
    ok_g, ok_q = on_curve(G, a, b, p), on_curve(Q, a, b, p)
    say(f"    G на кривой: {ok_g}; Q на кривой: {ok_q}")
    if not (ok_g and ok_q) and not force:
        say("[!] точка не лежит на кривой: скорее всего опечатка в параметрах. "
            "Если это намеренно — повтори с --force")
        return None

    sing = singular_attack(a, b, p)
    if sing:
        say(f"[!] {sing['hint']}" + (f" (x0={sing['x0']})" if sing.get("x0") is not None else ""))
        say("    инструмент не решает сингулярные кривые автоматически — "
            "нужен ручной переход к аддитивной/мультипликативной группе")
        return None

    n = params.get("n")
    if n is not None and n > 0 and mul(n, G, a, p) is not None and not force:
        say(f"[!] n={n} не является порядком G (n*G != O): DLP в такой "
            f"подгруппе не определён")
        return None

    if n:
        if n == p:
            say("[!] n == p: кривая аномальная, нужна атака Смарта "
                "(p-adic lift) — здесь её нет")
        fac = factorize(n)
        say(f"    порядок n={n}, разложение: {fac}")
        d, fac2 = pohlig_hellman(G, Q, n, a, p)
        if d is not None:
            say(f"[+] Полиг–Хеллман: d = {d}")
            return d
        d = bsgs(G, Q, n, a, p)
        if d is not None:
            say(f"[+] BSGS: d = {d}")
            return d
        say("[-] не вышло: порядок не гладкий и велик (или Q вне <G>)")
        return None

    d = bsgs(G, Q, 1 << 34, a, p)
    if d is not None:
        say(f"[+] BSGS (без порядка): d = {d}")
        return d
    say("[-] без порядка не нашлось: укажи n (порядок G), тогда сработает "
        "Полиг–Хеллман")
    return None


def main():
    ap = argparse.ArgumentParser(description="ECC: BSGS, Полиг–Хеллман, сингулярная кривая")
    ap.add_argument("--file", help="текст задачи с параметрами кривой")
    ap.add_argument("--p", type=int)
    ap.add_argument("--a", type=int)
    ap.add_argument("--b", type=int)
    ap.add_argument("--n", type=int)
    ap.add_argument("--gx", type=int)
    ap.add_argument("--gy", type=int)
    ap.add_argument("--qx", type=int)
    ap.add_argument("--qy", type=int)
    ap.add_argument("--force", action="store_true",
                    help="решать даже если точки не на кривой / n не порядок")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    params = {}
    if args.file:
        try:
            with open(args.file, encoding="utf-8", errors="replace") as fh:
                params.update(parse_text(fh.read()))
        except OSError as exc:
            print(f"[-] не прочитать файл: {exc}")
            return 2

    # CLI перекрывает только то, что реально передано (раньше --p затирал a/b)
    for key in ("p", "a", "b", "n"):
        val = getattr(args, key)
        if val is not None:
            params[key] = val
    if args.gx is not None and args.gy is not None:
        params["G"] = (args.gx, args.gy)
    if args.qx is not None and args.qy is not None:
        params["Q"] = (args.qx, args.qy)

    if not params:
        print("[-] параметров не нашлось: нужны p, a, b, G=(x,y), Q=(x,y)")
        return 1
    d = solve(params, verbose=not args.quiet, force=args.force)
    if d is None:
        return 1
    print(f"d = {d}") if args.quiet else None
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
