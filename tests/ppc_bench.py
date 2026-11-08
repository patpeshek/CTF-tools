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


TASKS = {
    "arith": g_arith, "missing": g_missing, "coprime_en": g_coprime_en,
    "coprime_ru": g_coprime_ru, "vowels": g_vowels, "prime": g_prime,
    "next_prime": g_next_prime, "divisors": g_divisors, "gcd": g_gcd,
    "factorial": g_factorial, "fib": g_fib, "reverse": g_reverse,
    "sort": g_sort, "seq": g_seq, "base": g_base, "date": g_date,
    "avg": g_avg, "logic": g_logic, "count": g_count, "max": g_max,
    "captcha": g_captcha,
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
