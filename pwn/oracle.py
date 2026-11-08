#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
oracle.py — универсальный TCP-оракул: прочитать → разобрать → посчитать → ответить.

Для сервисов вида «угадай/посчитай N раундов, потом флаг». Скрипт для каждого
задания не нужен: меняется только regex, формула и формат ответа.

  # готовый сценарий: два числа -> YES, если взаимно простые (ppc-раунды)
  python oracle.py --connect 127.0.0.1:31337 --preset coprime

  # простые числа, калькулятор, гласные/согласные, сумма
  python oracle.py --connect h:1 --preset prime
  python oracle.py --connect h:1 --preset calc
  python oracle.py --connect h:1 --preset vowels
  python oracle.py --connect h:1 --preset sum

  # то же руками: 100 раундов «a b» -> YES/NO
  python oracle.py --connect 127.0.0.1:31337 --match "(\\d+) +(\\d+)" \
      --expr "gcd(a,b) == 1" --send-expr "'YES' if v else 'NO'"

  # a^b mod m, ответ числом
  python oracle.py --connect h:1 --match "(?P<a>\\d+) (?P<b>\\d+) (?P<m>\\d+)" \
      --expr "pow(a,b,m)" --send "{v}"

  # сервис просит hex
  python oracle.py --connect h:1 --match "0x(?P<x>[0-9a-f]+)" --expr "int(x,16)*2" \
      --send "{v:x}"

  # вообще не знаю, что спросят: классифицировать и перебирать стратегии
  python oracle.py --connect h:1 --auto
  python oracle.py --connect h:1 --auto --promote 10 --attempts 20 --dump q.txt

  # посмотреть, что вообще присылает сервис (ничего не отвечать)
  python oracle.py --connect h:1 --peek

  # то же, но с локальным процессом вместо сети
  python oracle.py --local "python srv.py" --match "(\\d+) +(\\d+)" \
      --expr "gcd(a,b) == 1" --send-expr "'YES' if v else 'NO'"

Доступные в формулах имена: a..z из групп regex (по именам), nums, v, text,
gcd, lcm, is_prime, next_prime, modinv, xor, int, abs, min, max, sum, len,
pow, hex, chr, ord, round, sorted, bytes, str.

`--auto` — турнир стратегий, когда условие неизвестно. Вопрос классифицируется
(числа / простые / взаимно простые / гласные / слова / арифметика / base64 /
эмодзи / текст), берётся самая вероятная гипотеза ответа. Если сервис принял
`--promote` раундов подряд (по умолчанию 10) — стратегия закрепляется за
классом. Если соединение оборвалось или сервис сказал «wrong» — гипотеза
помечается неудачной, переподключение и следующая гипотеза. Всё, что не
понял, пишется в `--dump`, чтобы добавить правило.
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
import ast
import math
import os
import re
import socket
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import common  # noqa: E402
import ppc_solvers  # noqa: E402

ALLOWED_NODES = (
    ast.Expression, ast.BinOp, ast.UnaryOp, ast.BoolOp, ast.Compare, ast.Call,
    ast.Name, ast.Load, ast.Constant, ast.IfExp, ast.Tuple, ast.List, ast.Subscript,
    ast.Slice, ast.Add, ast.Sub, ast.Mult, ast.Div, ast.FloorDiv, ast.Mod, ast.Pow,
    ast.BitAnd, ast.BitOr, ast.BitXor, ast.LShift, ast.RShift, ast.USub, ast.UAdd,
    ast.Not, ast.Invert, ast.And, ast.Or, ast.Eq, ast.NotEq, ast.Lt, ast.LtE,
    ast.Gt, ast.GtE, ast.In, ast.NotIn,
)


def is_prime(n):
    if n < 2:
        return False
    if n % 2 == 0:
        return n == 2
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for a in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
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


def next_prime(n):
    n = max(2, int(n))
    while not is_prime(n):
        n += 1
    return n


def modinv(a, m):
    return pow(a, -1, m)


def xor(a, b):
    if isinstance(a, int) and isinstance(b, int):
        return a ^ b
    a = a if isinstance(a, bytes) else str(a).encode()
    b = b if isinstance(b, bytes) else str(b).encode()
    return bytes(x ^ b[i % len(b)] for i, x in enumerate(a))


def _calc(a, op, b):
    """a <op> b для пресета calc (без eval)."""
    a, b = float(a), float(b)
    if op == "+":
        return a + b
    if op == "-":
        return a - b
    if op == "*":
        return a * b
    if op == "/":
        return a / b
    if op == "%":
        return a % b
    raise ValueError(f"неизвестный оператор {op!r}")


def _tidy(value):
    """Целое без .0, иначе как есть."""
    if isinstance(value, float) and value.is_integer():
        return int(value)
    return value


def _vowels(text: str) -> int:
    return sum(ch in "aeiouyAEIOUY" for ch in text)


def _consonants(text: str) -> int:
    return sum(ch.isalpha() and ch not in "aeiouyAEIOUY" for ch in text)


SAFE = {
    "gcd": math.gcd, "lcm": math.lcm, "is_prime": is_prime, "next_prime": next_prime,
    "modinv": modinv, "xor": xor, "int": int, "abs": abs, "min": min, "max": max,
    "sum": sum, "len": len, "pow": pow, "hex": hex, "chr": chr, "ord": ord,
    "round": round, "sorted": sorted, "bytes": bytes, "str": str,
    "_calc": _calc, "_tidy": _tidy, "_vowels": _vowels, "_consonants": _consonants,
}


def safe_eval(code: str, ctx: dict):
    """Вычислить формулу в ограниченном окружении (без eval/импортов)."""
    tree = ast.parse(code.strip(), mode="eval")
    for node in ast.walk(tree):
        if not isinstance(node, ALLOWED_NODES):
            raise ValueError(f"в формуле запрещено: {type(node).__name__}")
        if isinstance(node, ast.Call) and not isinstance(node.func, ast.Name):
            raise ValueError("вызывать можно только именованные функции")
    return eval(compile(tree, "<expr>", "eval"), {"__builtins__": {}}, {**SAFE, **ctx})  # noqa: S307


class Conn:
    """Сокет или локальный процесс — одинаковый интерфейс."""

    def __init__(self, sock):
        self.s = sock
        self.s.settimeout(0.3)
        self.log = []

    def read_quiet(self, quiet_rounds=2, limit=65536):
        chunks = []
        idle = 0
        while idle < quiet_rounds and sum(map(len, chunks)) < limit:
            try:
                d = self.s.recv(4096)
            except socket.timeout:
                idle += 1
                continue
            if not d:
                break
            chunks.append(d)
            idle = 0
        data = b"".join(chunks)
        if data:
            self.log.append(("in", data))
        return data

    def send(self, data: bytes):
        self.s.sendall(data)
        self.log.append(("out", data))

    def close(self):
        try:
            self.s.close()
        except OSError:
            pass


class ProcConn:
    """Локальный процесс: тот же цикл, но через stdin/stdout."""

    def __init__(self, cmd: str):
        import queue
        import shlex
        import subprocess
        import threading

        self._queue = queue
        self.log = []
        args = shlex.split(cmd, posix=False)
        self.p = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  stderr=subprocess.STDOUT, bufsize=0)
        self.q = queue.Queue()
        threading.Thread(target=self._reader, daemon=True).start()

    def _reader(self):
        while True:
            try:
                d = self.p.stdout.read(4096)
            except Exception:
                break
            if not d:
                break
            self.q.put(d)

    def read_quiet(self, quiet_rounds=2, limit=65536):
        chunks = []
        idle = 0
        while idle < quiet_rounds and sum(map(len, chunks)) < limit:
            try:
                d = self.q.get(timeout=0.3)
            except self._queue.Empty:
                idle += 1
                if self.p.poll() is not None:
                    break
                continue
            chunks.append(d)
            idle = 0
        data = b"".join(chunks)
        if data:
            self.log.append(("in", data))
        return data

    def send(self, data: bytes):
        try:
            self.p.stdin.write(data)
            self.p.stdin.flush()
        except (BrokenPipeError, OSError):
            pass
        self.log.append(("out", data))

    def close(self):
        try:
            self.p.stdin.close()
        except OSError:
            pass
        self.p.terminate()

PRESETS = {
    # Два числа, ответ YES, если взаимно простые (типовой ppc-раунд).
    "coprime": dict(match=r"(\d+)\D+(\d+)", expr="gcd(a, b) == 1",
                    send_expr="'YES' if v else 'NO'"),
    # Одно число, ответ YES/NO на простоту.
    "prime": dict(match=r"(\d+)", expr="is_prime(n1)", send_expr="'YES' if v else 'NO'"),
    # «посчитай количество гласных и согласных» — два числа через пробел.
    "vowels": dict(match=r"([A-Za-z][A-Za-z ,.'-]{5,})", expr="(_vowels(a), _consonants(a))",
                   send_expr="f'{v[0]} {v[1]}'"),
    # Простой калькулятор: a + b.
    "calc": dict(match=r"(-?\d+(?:\.\d+)?)\s*([-+*/%])\s*(-?\d+(?:\.\d+)?)",
                 expr="_calc(a, b, c)", send_expr="str(_tidy(v))"),
    # Сумма двух чисел.
    "sum": dict(match=r"(-?\d+)\D+(-?\d+)", expr="a + b"),
}


def build_ctx(match: re.Match | None, text: str) -> dict:
    ctx = {"text": text, "nums": [], "v": 0}
    if not match:
        return ctx
    if match.groupdict():
        for k, val in match.groupdict().items():
            try:
                ctx[k] = int(val)
            except (TypeError, ValueError):
                ctx[k] = val
    for i, g in enumerate(match.groups(), 1):
        if g is None:
            ctx[f"n{i}"] = None
            continue
        try:
            num = int(g)
        except ValueError:
            ctx[f"n{i}"] = g
            if i <= 26:
                ctx[chr(96 + i)] = g
            continue
        ctx[f"n{i}"] = num
        ctx["nums"].append(num)
        if i <= 26:
            ctx[chr(96 + i)] = num  # a, b, c ... по порядку групп
    if ctx["nums"]:
        ctx["v"] = ctx["nums"][-1]
    return ctx


# --- авто-режим: стратегии ответов и их классификация -----------------------

WRONG_RE = re.compile(
    r"\bwrong\b|\bincorrect\b|\binvalid\b|\bdenied\b|неверн|ошибк|не так|"
    r"попробуй (ещё|снова)|try again", re.I)

EMOJI_RE = re.compile("[\U0001F000-\U0001FAFF\u2600-\u27BF]")


def _ask_lines(text: str, limit: int = 3) -> str:
    """Последние содержательные строки: там обычно сам вопрос."""
    lines = [l.strip() for l in text.splitlines() if l.strip()]
    keep = []
    for line in reversed(lines):
        low = line.lower().strip(":> ")
        if low in ("answer", "ответ", "your answer", ">", "?"):
            continue
        keep.append(line)
        if len(keep) >= limit:
            break
    return "\n".join(reversed(keep))


def _ints(text: str):
    """Числа из вопроса, без «раунд 3» и «попытка 2»."""
    cleaned = re.sub(r"(?i)(round|раунд|попытк\w*|attempt)\s*[:#]?\s*\d+", " ", text)
    return [int(x) for x in re.findall(r"-?\d+", cleaned)]


def _quoted(text: str):
    m = re.search(r"['\"«`]([^'\"»`]{1,300})['\"»`]", text)
    if m:
        return m.group(1)
    return None


def _data_text(text: str):
    """Строка с данными, а не с инструкцией («how many vowels...»)."""
    q = _quoted(text)
    if q:
        return q
    lines = [l.strip() for l in text.splitlines() if l.strip()]
    for line in reversed(lines):
        low = line.lower()
        if re.search(r"vowel|consonant|гласн|согласн|сколько|count|how many|"
                     r"answer|ответ", low):
            continue
        if ":" in line:
            tail = line.split(":", 1)[1].strip()
            if tail:
                return tail
        if "?" not in line:
            return line
    return None


def _st_coprime(t):
    n = _ints(t)
    if len(n) < 2:
        return None
    return "YES" if math.gcd(n[0], n[1]) == 1 else "NO"


def _st_sum(t):
    n = _ints(t)
    return str(sum(n)) if n else None


def _st_product(t):
    n = _ints(t)
    if not n:
        return None
    p = 1
    for x in n:
        p *= x
    return str(p)


def _st_max(t):
    n = _ints(t)
    return str(max(n)) if n else None


def _st_min(t):
    n = _ints(t)
    return str(min(n)) if n else None


def _st_gcd(t):
    n = _ints(t)
    if len(n) < 2:
        return None
    g = 0
    for x in n:
        g = math.gcd(g, x)
    return str(g)


def _st_lcm(t):
    n = _ints(t)
    if len(n) < 2:
        return None
    v = 1
    for x in n:
        v = math.lcm(v, x)
    return str(v)


def _st_is_prime(t):
    n = _ints(t)
    if not n:
        return None
    return "YES" if is_prime(abs(n[0])) else "NO"


def _st_next_prime(t):
    n = _ints(t)
    return str(next_prime(n[0])) if n else None


def _st_divisors(t):
    n = _ints(t)
    if not n or n[0] <= 0:
        return None
    x, cnt = n[0], 0
    for d in range(1, int(x ** 0.5) + 1):
        if x % d == 0:
            cnt += 1 if d * d == x else 2
    return str(cnt)


def _st_digit_sum(t):
    n = _ints(t)
    return str(sum(int(c) for c in str(abs(n[0])))) if n else None


def _st_reverse_digits(t):
    n = _ints(t)
    return str(abs(n[0]))[::-1] if n else None


def _st_vowels_pair(t):
    src = _data_text(t)
    if not re.search(r"[A-Za-zА-Яа-яЁё]", src):
        return None
    v = sum(ch in "aeiouyAEIOUYаеёиоуыэюяАЕЁИОУЫЭЮЯ" for ch in src)
    c = sum(ch.isalpha() and ch not in "aeiouyAEIOUYаеёиоуыэюяАЕЁИОУЫЭЮЯ" for ch in src)
    return f"{v} {c}"


def _st_count_vowels(t):
    src = _data_text(t)
    if not re.search(r"[A-Za-zА-Яа-яЁё]", src):
        return None
    return str(sum(ch in "aeiouyAEIOUYаеёиоуыэюяАЕЁИОУЫЭЮЯ" for ch in src))


def _st_count_consonants(t):
    src = _data_text(t)
    if not re.search(r"[A-Za-zА-Яа-яЁё]", src):
        return None
    return str(sum(ch.isalpha() and ch not in "aeiouyAEIOUYаеёиоуыэюяАЕЁИОУЫЭЮЯ"
                   for ch in src))


def _st_word_count(t):
    src = _data_text(t)
    words = re.findall(r"[A-Za-zА-Яа-яЁё0-9_]+", src)
    return str(len(words)) if words else None


def _st_char_count(t):
    src = _data_text(t)
    return str(len(src)) if src else None


def _st_reverse(t):
    src = _data_text(t)
    return src[::-1] if src else None


def _st_eval_expr(t):
    cand = re.findall(r"[0-9()\s+\-*/%.]{3,}", t)
    for expr in sorted(cand, key=len, reverse=True):
        if not re.search(r"\d\s*[-+*/%]\s*\d", expr):
            continue
        try:
            val = safe_eval(expr, {})
        except Exception:
            continue
        return str(_tidy(val))
    return None


def _st_b64(t):
    for tok in re.findall(r"[A-Za-z0-9+/=]{8,}", t):
        try:
            import base64
            raw = base64.b64decode(tok + "=" * (-len(tok) % 4), validate=True)
            out = raw.decode("utf-8")
            if out.isprintable():
                return out
        except Exception:
            continue
    return None


def _st_hex(t):
    for tok in re.findall(r"(?:[0-9a-fA-F]{2}){4,}", t):
        try:
            out = bytes.fromhex(tok).decode("utf-8")
            if out.isprintable():
                return out
        except Exception:
            continue
    return None


def _st_emoji_count(t):
    found = EMOJI_RE.findall(t)
    return str(len(found)) if found else None


def _st_emoji_unique(t):
    found = EMOJI_RE.findall(t)
    return str(len(set(found))) if found else None


def _lower(value):
    return value.lower() if value else None


def _st_coprime_lower(t):
    r = _st_coprime(t)
    return r.lower() if r else None


def _st_is_prime_lower(t):
    r = _st_is_prime(t)
    return r.lower() if r else None


def _st_vowels_comma(t):
    r = _st_vowels_pair(t)
    return r.replace(" ", ",") if r else None


STRATEGIES = {
    "coprime": _st_coprime, "sum": _st_sum, "product": _st_product,
    "max": _st_max, "min": _st_min, "gcd": _st_gcd, "lcm": _st_lcm,
    "is_prime": _st_is_prime, "next_prime": _st_next_prime,
    "divisors": _st_divisors, "digit_sum": _st_digit_sum,
    "reverse_digits": _st_reverse_digits,
    "vowels_pair": _st_vowels_pair, "count_vowels": _st_count_vowels,
    "count_consonants": _st_count_consonants, "word_count": _st_word_count,
    "char_count": _st_char_count, "reverse": _st_reverse,
    "eval_expr": _st_eval_expr, "b64decode": _st_b64, "hexdecode": _st_hex,
    "emoji_count": _st_emoji_count, "emoji_unique": _st_emoji_unique,
    "coprime_lower": _st_coprime_lower, "is_prime_lower": _st_is_prime_lower,
    "vowels_comma": _st_vowels_comma,
}


def classify(text: str) -> tuple[str, list[str]]:
    """Класс вопроса и упорядоченный список гипотез-стратегий."""
    low = text.lower()
    if re.search(r"[0-9)]\s*[-+*/%]\s*[0-9(]", text):
        return "arith", ["eval_expr", "sum"]
    if re.search(r"взаимно\s*прост|coprime|\bgcd\b", low):
        return "coprime", ["coprime", "gcd", "sum"]
    if re.search(r"гласн|vowel", low):
        return "vowels", ["vowels_pair", "count_vowels", "count_consonants"]
    if re.search(r"согласн|consonant", low) and not re.search(r"гласн|vowel", low):
        return "consonants", ["count_consonants", "vowels_pair"]
    if re.search(r"сколько\s+слов|number of words|word count", low):
        return "words", ["word_count", "char_count"]
    if re.search(r"переверн|reverse|задом наперёд", low):
        return "reverse", ["reverse"]
    if re.search(r"base64|декодир|decode", low):
        return "decode", ["b64decode", "hexdecode"]
    if re.search(r"прост(ое|ые|ых)|\bprime\b", low) and not re.search(r"взаимно", low):
        return "prime", ["is_prime", "next_prime"]
    if EMOJI_RE.search(text):
        return "emoji", ["emoji_count", "emoji_unique"]
    if re.search(r"произвед|product|multipl", low):
        return "product", ["product", "sum"]
    if re.search(r"сумм|\bsum\b|итог|total", low):
        return "sum", ["sum", "product"]
    n = _ints(_ask_lines(text))
    if len(n) >= 2:
        return "nums2", ["coprime", "sum", "product", "max", "min", "gcd", "lcm"]
    if len(n) == 1:
        return "int1", ["is_prime", "divisors", "digit_sum", "reverse_digits",
                        "next_prime"]
    if _quoted(text):
        return "text", ["vowels_pair", "word_count", "char_count", "reverse"]
    return "unknown", []


def auto_run(args) -> int:
    """Турнир стратегий: правильно 10 раундов подряд — закрепляем."""
    import time as _time

    if args.local:
        def connect():
            return ProcConn(args.local)
    else:
        host, _, port = args.connect.rpartition(":")
        if not host or not port.isdigit():
            print("[-] --connect должен быть host:port")
            return 2

        def connect():
            return Conn(socket.create_connection((host, int(port)), timeout=3.0))

    tried = {}      # класс -> множество провалившихся стратегий
    trusted = {}    # класс -> стратегия, которая держится
    started = _time.time()
    attempts = 0
    flag = None
    dump = []
    grab = common.FlagGrabber()

    while attempts < args.attempts:
        attempts += 1
        if args.time and _time.time() - started > args.time:
            print(f"[i] вышло время ({args.time} с), останавливаюсь")
            break
        try:
            conn = connect()
        except OSError as e:
            print(f"[-] не подключаюсь: {e}")
            return 2

        streak = 0
        current = None
        cls = None
        promoted = False
        stuck = False
        prev_text = None
        rounds = 0
        print(f"\n=== попытка {attempts} ===")
        while rounds < args.rounds:
            data = conn.read_quiet()
            if not data:
                break
            text = data.decode("utf-8", "replace")
            dump.append(text)
            if args.show_transcript:
                print(text.rstrip()[:800])

            found = grab.feed(data)
            if found:
                flag = found[0]
                print("[!!!] ФЛАГ:", " | ".join(found))
                break
            if WRONG_RE.search(text):
                print("[i] сервис ругается — меняю стратегию")
                break
            prev_text = text.strip()

            ppc = ppc_solvers.candidates(text)
            if ppc:
                cls = "ppc"
                options = [name for name, _ in ppc]
                answers = dict(ppc)
            else:
                cls, options = classify(text)
                answers = {}
            if not options:
                print(f"[?] не понял вопрос ({cls}): {text.strip()[:200]!r}")
                stuck = True
                break

            if cls in trusted:
                name = trusted[cls]
            else:
                bad = tried.get(cls, set())
                name = next((o for o in options if o not in bad), None)
                if name is None:
                    print(f"[?] для класса {cls} кончились гипотезы")
                    break

            answer = answers[name] if cls == "ppc" else STRATEGIES[name](text)
            if answer is None:
                print(f"[?] стратегия {name} не смогла разобрать: {text.strip()[:160]!r}")
                tried.setdefault(cls, set()).add(name)
                stuck = True
                break

            if name != current:
                print(f"[i] {cls}: пробую {name} -> {answer!r}")
                current = name
            conn.send((answer + "\n").encode())
            streak += 1
            rounds += 1
            if streak == args.promote and cls not in trusted:
                trusted[cls] = name
                promoted = True
                print(f"[+] {cls}: {name} держится {streak} раундов подряд — закрепляю")

        conn.close()
        if flag:
            break
        if stuck:
            print("[i] дальше без нового правила смысла нет — добавляй класс в classify")
            break

        # сессия кончилась без флага: если закрепиться не успели — гипотеза мимо
        if current and cls and not promoted and streak < args.promote:
            tried.setdefault(cls, set()).add(current)
            print(f"[-] {cls}: {current} не сработала (раундов до обрыва: {streak})")
        _time.sleep(0.2)

    print(f"\n[i] попыток: {attempts}; закреплено: "
          + (", ".join(f"{k}={v}" for k, v in trusted.items()) or "ничего"))
    if args.dump:
        with open(args.dump, "w", encoding="utf-8") as f:
            f.write("\n---\n".join(dump))
        print(f"[i] все вопросы сохранены: {args.dump}")
        print("[i] новый тип вопроса? добавь стратегию в STRATEGIES и правило в classify")
    if args.log:
        with open(args.log, "w", encoding="utf-8") as f:
            f.write("\n---\n".join(dump))
    return 0 if flag else 1


def main():
    ap = argparse.ArgumentParser(epilog=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--connect", help="host:port сервиса")
    ap.add_argument("--local", help="локальная команда процесса, напр. \"python srv.py\"")
    ap.add_argument("--preset", choices=sorted(PRESETS),
                    help="готовый сценарий: " + ", ".join(sorted(PRESETS)))
    ap.add_argument("--match", help="regex вопроса; группы становятся переменными")
    ap.add_argument("--expr", help="что посчитать (python-подобно); по умолчанию v")
    ap.add_argument("--send", help="шаблон ответа, напр. '{v}' или 'YES'")
    ap.add_argument("--send-expr", help="ответ как формула, напр. \"'YES' if v else 'NO'\"")
    ap.add_argument("--repeat", type=int, default=200, help="максимум раундов")
    ap.add_argument("--until", help="остановиться, когда в ответе встретится regex")
    ap.add_argument("--peek", action="store_true", help="только читать, не отвечать")
    ap.add_argument("--auto", action="store_true",
                    help="авто-режим: сам классифицирует вопрос и перебирает стратегии")
    ap.add_argument("--promote", type=int, default=10,
                    help="сколько раундов подряд нужно, чтобы закрепить стратегию")
    ap.add_argument("--attempts", type=int, default=20,
                    help="сколько переподключений делать в авто-режиме")
    ap.add_argument("--rounds", type=int, default=500,
                    help="максимум раундов за одно соединение (авто)")
    ap.add_argument("--time", type=float, default=0, help="общий лимит времени, сек (0=нет)")
    ap.add_argument("--dump", help="сохранить все вопросы авто-режима в файл")
    ap.add_argument("--delay", type=float, default=0.0, help="пауза перед ответом, сек")
    ap.add_argument("--log", help="писать транскрипт в файл")
    ap.add_argument("--show-transcript", action="store_true", help="печатать всё, что пришло")
    common.add_flag_args(ap)
    args = ap.parse_args()
    common.apply_flag_args(args)

    if args.preset:
        preset = PRESETS[args.preset]
        if args.match is None:
            args.match = preset["match"]
        if args.expr is None:
            args.expr = preset["expr"]
        if args.send is None and args.send_expr is None:
            args.send_expr = preset.get("send_expr")
        print(f"[i] пресет: {args.preset}")
    if args.expr is None:
        args.expr = "v"

    if bool(args.connect) == bool(args.local):
        ap.error("нужен ровно один из --connect host:port или --local \"команда\"")
    if args.auto:
        return auto_run(args)
    if not args.match and not args.peek:
        ap.error("нужен --match (что вытащить из вопроса) или --peek (только посмотреть)")

    if args.local:
        conn = ProcConn(args.local)
    else:
        host, _, port = args.connect.rpartition(":")
        if not host or not port.isdigit():
            ap.error("--connect должен быть host:port")
        conn = Conn(socket.create_connection((host, int(port)), timeout=3.0))
    until_re = re.compile(args.until) if args.until else None
    flag_re = common.FLAG_RE
    grab = common.FlagGrabber()

    answered = 0
    for round_no in range(1, args.repeat + 1):
        data = conn.read_quiet()
        if not data:
            if round_no == 1:
                print("[-] сервер молчит или закрыл соединение")
            break
        text = data.decode("utf-8", "replace")
        if args.show_transcript or args.peek:
            print(f"--- раунд {round_no} ---")
            print(text.rstrip())

        flags = grab.feed(data)
        if flags:
            print("[!!!] ФЛАГ:", " | ".join(flags))
            break
        if until_re and until_re.search(text):
            print("[+] достигнут --until, стоп")
            break
        if args.peek:
            continue

        m = re.search(args.match, text, re.S) if args.match else None
        if args.match and not m:
            print(f"[-] regex не нашёл вопроса в раунде {round_no}; транскрипт:")
            print(text.rstrip()[:2000])
            break
        ctx = build_ctx(m, text)
        try:
            val = safe_eval(args.expr, ctx)
        except Exception as e:
            print(f"[-] формула упала в раунде {round_no}: {e}")
            print("    вопрос:", text.rstrip()[:500])
            break

        if args.send_expr:
            try:
                answer = str(safe_eval(args.send_expr, {**ctx, "v": val}))
            except Exception as e:
                print(f"[-] --send-expr упал: {e}")
                break
        elif args.send is not None:
            try:
                answer = args.send.format(**ctx, v=val)
            except (KeyError, IndexError) as e:
                print(f"[-] --send: нет поля {e}; доступно: v, n1.., имена групп")
                break
        else:
            answer = str(val)

        if not answer.endswith("\n"):
            answer += "\n"
        if args.delay:
            time.sleep(args.delay)
        conn.send(answer.encode())
        answered += 1

    conn.close()
    print(f"[+] раундов с ответом: {answered}")
    if args.log:
        with open(args.log, "w", encoding="utf-8") as f:
            for direction, payload in conn.log:
                f.write(f"{direction}: {payload.decode('utf-8', 'replace')}\n")
        print(f"[+] транскрипт: {args.log}")


if __name__ == "__main__":
    main()
