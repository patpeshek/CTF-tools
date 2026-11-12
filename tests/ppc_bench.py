#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ppc_bench.py — локальный стенд PPC: 20 задач RU/EN, реальные TCP-сервисы.

Запускает по сервису на задачу (N раундов, обрыв на ошибке, флаг в конце) и
прогоняет `pwn/oracle.py --auto`. Показывает, сколько типов задач движок
решает сам, без подсказок и плагинов.

  python tests/ppc_bench.py
  python tests/ppc_bench.py --only arith,vowels
"""
from __future__ import annotations

import argparse
import math
import os
import random
import socket
import subprocess
import sys
import threading
import time

KIT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PY = sys.executable
ROUNDS = 4


def feedback(guess, target):
    g, t = list(guess), list(target)
    res = ["b"] * len(g)
    cnt = {}
    for ch in t:
        cnt[ch] = cnt.get(ch, 0) + 1
    for i, (a, b) in enumerate(zip(g, t)):
        if a == b:
            res[i] = "g"
            cnt[a] -= 1
    for i, a in enumerate(g):
        if res[i] == "b" and cnt.get(a, 0) > 0:
            res[i] = "y"
            cnt[a] -= 1
    return res


def norm(s: str) -> str:
    return " ".join(str(s).strip().lower().split())


# ------------------------------- генераторы (вопрос, правильный ответ)

def g_arith(_i):
    a, b, c, d = (random.randint(2, 60) for _ in range(4))
    return f"Посчитай: {a} + {b} * {c} - {d}", str(a + b * c - d)


def g_missing(_i):
    a, b = random.randint(10, 99), random.randint(10, 99)
    op = random.choice("+-*")
    val = {"+": a + b, "-": a - b, "*": a * b}[op]
    return f"{a} ? {b} = {val}", op


def g_coprime_en(_i):
    a, b = random.randint(2000, 25000), random.randint(2000, 25000)
    return f"Are {a} and {b} coprime? Answer YES or NO.", \
           "YES" if math.gcd(a, b) == 1 else "NO"


def g_coprime_ru(_i):
    a, b = random.randint(2000, 25000), random.randint(2000, 25000)
    return f"Числа {a} и {b} взаимно простые? Ответ YES или NO.", \
           "YES" if math.gcd(a, b) == 1 else "NO"


def g_vowels(_i):
    w = random.choice(["hello world", "stack overflow", "привет мир", "олимпиада"])
    v = sum(ch in "aeiouyаеёиоуыэюя" for ch in w.lower())
    c = sum(ch.isalpha() and ch not in "aeiouyаеёиоуыэюя" for ch in w.lower())
    return f'Сколько гласных и согласных в строке "{w}"?', f"{v} {c}"


def g_prime(_i):
    n = random.choice([97, 91, 113, 121, 127, 143])
    is_p = all(n % d for d in range(2, int(n ** 0.5) + 1)) and n > 1
    return f"Is {n} prime? YES or NO", "YES" if is_p else "NO"


def g_next_prime(_i):
    n = random.randint(50, 300)
    m = n + 1
    while True:
        if all(m % d for d in range(2, int(m ** 0.5) + 1)) and m > 1:
            break
        m += 1
    return f"Следующее простое число после {n}?", str(m)


def g_divisors(_i):
    n = random.randint(12, 200)
    cnt = sum(1 for d in range(1, n + 1) if n % d == 0)
    return f"How many divisors does {n} have?", str(cnt)


def g_gcd(_i):
    a, b = random.randint(20, 500), random.randint(20, 500)
    return f"Чему равен НОД чисел {a} и {b}?", str(math.gcd(a, b))


def g_factorial(_i):
    n = random.randint(4, 9)
    return f"factorial of {n} is?", str(math.factorial(n))


def g_fib(_i):
    n = random.randint(6, 15)
    a, b = 0, 1
    for _ in range(n):
        a, b = b, a + b
    return f"Какое {n}-е число Фибоначчи?", str(a)


def g_reverse(_i):
    w = random.choice(["hello", "olympiad", "network", "reverse"])
    return f"Reverse the string '{w}'", w[::-1]


def g_sort(_i):
    xs = [random.randint(1, 99) for _ in range(5)]
    return "Отсортируй по возрастанию: " + " ".join(map(str, xs)), \
           " ".join(map(str, sorted(xs)))


def g_seq(_i):
    d = random.randint(2, 9)
    a = random.randint(1, 20)
    seq = [a + d * k for k in range(4)]
    return "Продолжи последовательность: " + ", ".join(map(str, seq)), str(a + 4 * d)


def g_base(_i):
    n = random.randint(16, 255)
    return f"Переведи {n} в шестнадцатеричную систему", format(n, "x")


def g_date(_i):
    import datetime
    d = datetime.date(2026, random.randint(1, 12), random.randint(1, 28))
    wd = ["понедельник", "вторник", "среда", "четверг", "пятница", "суббота",
          "воскресенье"][d.weekday()]
    return f"Какой день недели {d.strftime('%Y-%m-%d')}?", wd


def g_avg(_i):
    xs = [random.randint(1, 20) for _ in range(4)]
    while sum(xs) % 4:
        xs = [random.randint(1, 20) for _ in range(4)]
    return "average of " + " ".join(map(str, xs)), str(sum(xs) // 4)


def g_logic(_i):
    a, b = random.choice([(True, False), (True, True), (False, False)])
    expr = f"{'истина' if a else 'ложь'} и {'истина' if b else 'ложь'} или истина"
    return f"Результат выражения: {expr}", "YES"


def g_count(_i):
    w = random.choice(["banana", "mississippi", "olympiad"])
    ch = random.choice("ai")
    return f"Сколько раз встречается '{ch}' в '{w}'?", str(w.count(ch))


def g_max(_i):
    xs = [random.randint(1, 99) for _ in range(5)]
    return "Максимум из чисел: " + " ".join(map(str, xs)), str(max(xs))


def g_captcha(_i):
    import base64
    import io
    import string
    from PIL import Image, ImageDraw, ImageFont
    word = "".join(random.choices(string.ascii_uppercase + string.digits, k=4))
    im = Image.new("RGB", (260, 90), "white")
    d = ImageDraw.Draw(im)
    try:
        font = ImageFont.truetype(r"C:\Windows\Fonts\arialbd.ttf", 64)
    except Exception:
        font = ImageFont.load_default()
    d.text((12, 8), word, fill="black", font=font)
    buf = io.BytesIO()
    im.save(buf, "PNG")
    b64 = base64.b64encode(buf.getvalue()).decode()
    return f"Введите слово с картинки (captcha): {b64}", word


# ---- алгоритмические задачи категории MATH (ticket #89) --------------------
# Ответы считаются независимо (hashlib/math/самостоятельные алгоритмы), а не
# вызовом решателя, иначе тест проверял бы сам себя.


def _rand_word():
    import string
    return "".join(random.choices(string.ascii_lowercase, k=random.randint(4, 8)))


def g_hash_md5(_i):
    import hashlib
    w = _rand_word()
    return f"md5 of '{w}'", hashlib.md5(w.encode()).hexdigest()


def g_hash_sha1(_i):
    import hashlib
    w = _rand_word()
    return f"sha1 of '{w}'", hashlib.sha1(w.encode()).hexdigest()


def g_hash_sha256(_i):
    import hashlib
    w = _rand_word()
    return f"sha256 of '{w}'", hashlib.sha256(w.encode()).hexdigest()


def g_hash_sha512(_i):
    import hashlib
    w = _rand_word()
    return f"sha512 of '{w}'", hashlib.sha512(w.encode()).hexdigest()


def g_hash_crc32(_i):
    import zlib
    w = _rand_word()
    return f"crc32 of '{w}'", format(zlib.crc32(w.encode()) & 0xFFFFFFFF, "08x")


def g_modexp(_i):
    a = random.randint(2, 50)
    b = random.randint(2, 40)
    m = random.randint(100, 9999)
    return f"Compute {a}^{b} mod {m}", str(pow(a, b, m))


def g_modinv(_i):
    m = random.choice([97, 101, 103, 107, 109, 113, 1009, 10007])
    a = random.randint(2, m - 1)
    return f"Find the modular inverse of {a} mod {m}", str(pow(a, -1, m))


def g_crt(_i):
    mods = random.sample([3, 5, 7, 11, 13], 3)   # различные простые -> попарно взаимно просты
    res = [random.randint(0, mm - 1) for mm in mods]
    prod = 1
    for mm in mods:
        prod *= mm
    x = next(v for v in range(prod)
             if all(v % mm == r for mm, r in zip(mods, res)))
    parts = ", ".join(f"x ≡ {r} mod {mm}" for r, mm in zip(res, mods))
    return f"Solve the system: {parts}", str(x)


def g_factmod(_i):
    n = random.randint(5, 40)
    m = random.choice([1000000007, 998244353, 10007])
    return f"Compute {n}! mod {m}", str(math.factorial(n) % m)


def g_fibmod(_i):
    n = random.randint(10, 90)
    m = random.choice([1000000007, 998244353, 10007])
    a, b = 0, 1
    for _ in range(n):
        a, b = b, a + b
    return f"The {n}th Fibonacci number mod {m}", str(a % m)


def g_binom(_i):
    n = random.randint(5, 30)
    k = random.randint(0, n)
    p = random.choice([1000000007, 998244353, 10007])
    return f"Compute C({n}, {k}) mod {p}", str(math.comb(n, k) % p)


def _mr(n):
    """Детерминированный Miller–Rabin для n < 3.3e24 (независимая реализация)."""
    if n < 2:
        return False
    for pr in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % pr == 0:
            return n == pr
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for a in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def g_prime_big(_i):
    def rand_prime(lo, hi):
        x = random.randint(lo, hi)
        while not _mr(x):
            x += 1
        return x
    if random.random() < 0.5:
        n = rand_prime(10 ** 8, 10 ** 9) * rand_prime(10 ** 8, 10 ** 9)  # < 2^64
        return f"Is {n} prime? Answer YES or NO", "NO"
    n = rand_prime(10 ** 14, 10 ** 15)
    return f"Is {n} prime? Answer YES or NO", "YES"


def g_select_kth(_i):
    xs = random.sample(range(1, 99), random.randint(5, 8))
    k = random.randint(1, len(xs))
    suf = {1: "st", 2: "nd", 3: "rd"}.get(k if k < 20 else k % 10, "th")
    want = str(sorted(xs)[k - 1])
    return f"Find the {k}{suf} smallest of: " + ", ".join(map(str, xs)), want


def g_median(_i):
    xs = [random.randint(1, 99) for _ in range(random.choice([5, 7]))]
    s = sorted(xs)
    return "Median of: " + ", ".join(map(str, xs)), str(s[len(s) // 2])


def g_brackets(_i):
    pairs = "()[]{}"
    closes = {"(": ")", "[": "]", "{": "}"}
    if random.random() < 0.5:
        out, stack = [], []
        for _ in range(random.randint(2, 6)):
            if stack and random.random() < 0.5:
                out.append(closes[stack.pop()])
            else:
                o = random.choice("([{")
                stack.append(o)
                out.append(o)
        while stack:
            out.append(closes[stack.pop()])
        s = "".join(out) or "()"
    else:
        s = "".join(random.choice(pairs) for _ in range(random.randint(3, 7)))
    stack, ok = [], True
    for ch in s:
        if ch in "([{":
            stack.append(ch)
        elif not stack or closes[stack.pop()] != ch:
            ok = False
            break
    ok = ok and not stack
    return (f"Is '{s}' a balanced bracket string? Answer YES or NO",
            "YES" if ok else "NO")


def g_matmul(_i):
    def mat():
        return [[random.randint(0, 9) for _ in range(2)] for _ in range(2)]

    def fmt(m):
        return "[[" + "],[".join(",".join(map(str, r)) for r in m) + "]]"
    a, b = mat(), mat()
    p = random.choice([97, 1000, 1000000007])
    c = [[sum(a[i][k] * b[k][j] for k in range(2)) % p for j in range(2)]
         for i in range(2)]
    flat = " ".join(str(x) for row in c for x in row)
    return f"Multiply matrices {fmt(a)} and {fmt(b)} mod {p}", flat


def g_det(_i):
    def det(m):
        k = len(m)
        if k == 1:
            return m[0][0]
        if k == 2:
            return m[0][0] * m[1][1] - m[0][1] * m[1][0]
        tot = 0
        for c in range(k):
            minor = [row[:c] + row[c + 1:] for row in m[1:]]
            tot += ((-1) ** c) * m[0][c] * det(minor)
        return tot

    def fmt(m):
        return "[[" + "],[".join(",".join(map(str, r)) for r in m) + "]]"
    n = random.choice([2, 3])
    mat = [[random.randint(-5, 9) for _ in range(n)] for _ in range(n)]
    p = random.choice([97, 1000003, 1000000007])
    return f"Determinant of {fmt(mat)} mod {p}", str(det(mat) % p)


def _connected_edges(nodes, extra):
    """Связный граф: остовное дерево + несколько лишних рёбер (список пар)."""
    perm = random.sample(range(1, nodes + 1), nodes)
    edges = [(perm[i], perm[random.randint(0, i - 1)]) for i in range(1, nodes)]
    for _ in range(extra):
        a, b = random.randint(1, nodes), random.randint(1, nodes)
        if a != b:
            edges.append((a, b))
    random.shuffle(edges)
    return edges


def g_sp_unweighted(_i):
    import collections
    n = random.randint(5, 8)
    edges = _connected_edges(n, random.randint(1, 3))
    s = random.randint(1, n)
    t = random.randint(1, n)
    while t == s:
        t = random.randint(1, n)
    adj = collections.defaultdict(list)
    for u, v in edges:
        adj[u].append(v)
        adj[v].append(u)
    dist = {s: 0}
    dq = collections.deque([s])
    while dq:
        u = dq.popleft()
        for v in adj[u]:
            if v not in dist:
                dist[v] = dist[u] + 1
                dq.append(v)
    estr = " ".join(f"{u}-{v}" for u, v in edges)
    return (f"Unweighted graph edges: {estr}. "
            f"Shortest path length from {s} to {t}?"), str(dist[t])


def g_sp_weighted(_i):
    import collections
    import heapq
    n = random.randint(5, 8)
    base = _connected_edges(n, random.randint(1, 3))
    edges = [(u, v, random.randint(1, 9)) for (u, v) in base]
    s = random.randint(1, n)
    t = random.randint(1, n)
    while t == s:
        t = random.randint(1, n)
    adj = collections.defaultdict(list)
    for u, v, w in edges:
        adj[u].append((v, w))
        adj[v].append((u, w))
    dist = {s: 0}
    pq = [(0, s)]
    while pq:
        d, u = heapq.heappop(pq)
        if d > dist.get(u, math.inf):
            continue
        for v, w in adj[u]:
            nd = d + w
            if nd < dist.get(v, math.inf):
                dist[v] = nd
                heapq.heappush(pq, (nd, v))
    estr = " ".join(f"{u}-{v}:{w}" for u, v, w in edges)
    return (f"Weighted graph edges: {estr}. "
            f"Shortest path length from {s} to {t}?"), str(dist[t])


def g_components(_i):
    n = random.randint(5, 9)
    edges = []
    for _ in range(random.randint(2, n)):
        a, b = random.randint(1, n), random.randint(1, n)
        if a != b:
            edges.append((a, b))
    parent = list(range(n + 1))

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x
    for a, b in edges:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[ra] = rb
    comps = len({find(v) for v in range(1, n + 1)})
    estr = " ".join(f"{u}-{v}" for u, v in edges) if edges else "none"
    return (f"Graph with {n} nodes and edges: {estr}. "
            f"How many connected components?"), str(comps)


def g_topo(_i):
    import collections
    import heapq
    n = random.randint(4, 7)
    labels = random.sample(range(1, n + 1), n)
    edges = [(labels[i], labels[j]) for i in range(n) for j in range(i + 1, n)
             if random.random() < 0.4]            # i<j в порядке labels -> DAG
    if not edges:
        edges = [(labels[0], labels[1])]
    random.shuffle(edges)
    adj = collections.defaultdict(list)
    indeg = {}
    nodes = set()
    for u, v in edges:
        nodes.add(u)
        nodes.add(v)
        adj[u].append(v)
        indeg[v] = indeg.get(v, 0) + 1
        indeg.setdefault(u, indeg.get(u, 0))
    for v in nodes:
        indeg.setdefault(v, 0)
    heap = [v for v in nodes if indeg[v] == 0]
    heapq.heapify(heap)
    order = []
    while heap:
        u = heapq.heappop(heap)
        order.append(u)
        for v in sorted(adj[u]):
            indeg[v] -= 1
            if indeg[v] == 0:
                heapq.heappush(heap, v)
    estr = " ".join(f"{u}->{v}" for u, v in edges)
    return f"Directed graph edges: {estr}. Topological order?", \
           " ".join(map(str, order))


TASKS = {
    "arith": g_arith, "missing": g_missing, "coprime_en": g_coprime_en,
    "coprime_ru": g_coprime_ru, "vowels": g_vowels, "prime": g_prime,
    "next_prime": g_next_prime, "divisors": g_divisors, "gcd": g_gcd,
    "factorial": g_factorial, "fib": g_fib, "reverse": g_reverse,
    "sort": g_sort, "seq": g_seq, "base": g_base, "date": g_date,
    "avg": g_avg, "logic": g_logic, "count": g_count, "max": g_max,
    "captcha": g_captcha,
    # --- алгоритмические (ticket #89) ---
    "hash_md5": g_hash_md5, "hash_sha1": g_hash_sha1,
    "hash_sha256": g_hash_sha256, "hash_sha512": g_hash_sha512,
    "hash_crc32": g_hash_crc32,
    "modexp": g_modexp, "modinv": g_modinv, "crt": g_crt,
    "factmod": g_factmod, "fibmod": g_fibmod, "binom": g_binom,
    "prime_big": g_prime_big,
    "select_kth": g_select_kth, "median": g_median,
    "brackets": g_brackets, "matmul": g_matmul, "det": g_det,
    "sp_bfs": g_sp_unweighted, "sp_dijkstra": g_sp_weighted,
    "components": g_components, "topo": g_topo,
}


def serve(port, gen, stop, rounds):
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(8)
    srv.settimeout(0.5)

    def handle(c):
        f = c.makefile("rwb")
        try:
            for _ in range(rounds):
                q, want = gen(0)
                f.write((q + "\n").encode())
                f.flush()
                ans = f.readline().decode("utf-8", "replace")
                if not ans:
                    return
                if norm(ans) != norm(want):
                    f.write(b"wrong\n")
                    f.flush()
                    return
            f.write(b"CTF{bench_" + b"ok" + b"}\n")
            f.flush()
        except OSError:
            pass
        finally:
            try:
                c.close()
            except OSError:
                pass

    while not stop.is_set():
        try:
            c, _ = srv.accept()
        except socket.timeout:
            continue
        except OSError:
            break
        threading.Thread(target=handle, args=(c,), daemon=True).start()
    srv.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", help="список задач через запятую")
    ap.add_argument("--rounds", type=int, default=ROUNDS)
    args = ap.parse_args()

    names = [n for n in (args.only.split(",") if args.only else TASKS)]
    random.seed(7)
    stop = threading.Event()
    servers = []
    for i, name in enumerate(names):
        port = 31700 + i
        threading.Thread(target=serve, args=(port, TASKS[name], stop, args.rounds),
                         daemon=True).start()
        servers.append((name, port))
    time.sleep(0.6)

    ok = 0
    results = []
    for name, port in servers:
        cmd = [PY, os.path.join(KIT, "pwn", "oracle.py"), "--connect",
               f"127.0.0.1:{port}", "--auto", "--promote", "3",
               "--attempts", "5", "--rounds", "20"]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True,
                               encoding="utf-8", errors="replace", timeout=45,
                               env=dict(os.environ, PYTHONIOENCODING="utf-8"))
            out = (r.stdout or "") + (r.stderr or "")
            good = "CTF{bench_ok}" in out
        except subprocess.TimeoutExpired:
            out, good = "timeout", False
        ok += good
        results.append((name, good, out))
        print(f"{'PASS' if good else 'FAIL'}  {name}")
        if not good:
            print("      " + out.strip().replace("\n", "\n      ")[:500])

    stop.set()
    print(f"\n=== {ok}/{len(servers)} ===")
    return 0 if ok == len(servers) else 1


if __name__ == "__main__":
    sys.exit(main())
