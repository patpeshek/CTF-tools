#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ppc_solvers.py — библиотека решателей для PPC-задач «ответь N раундов».

Задача модуля: по тексту вопроса понять, что просят, и вернуть несколько
вариантов ответа (от самого вероятного к менее вероятному). Движок
(`oracle --auto`, `game_bot`) перебирает их, закрепляет рабочий вариант после
серии успехов и меняет гипотезу после обрыва.

Покрывает: арифметику и цепочки выражений, недостающий оператор, простые
числа, НОД/НОК, делители, факториал, Фибоначчи, цифры, строки (реверс,
гласные, слова, палиндром), сортировку, последовательности, системы
счисления, степени/модули, даты, кодировки, замену/подсчёт подстроки,
логические выражения, среднее/мин/макс/сумму.

Чего не делает: не «понимает» свободный текст без ключевых слов и не решает
NLP/ML-классификацию (для этого нужен словарь/модель) — в таких случаях
возвращает пустой список, и движок честно просит плагин.
"""
from __future__ import annotations

try:
    import sys as _sys
    for _stream in (_sys.stdout, _sys.stderr):
        _stream.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

import datetime as _dt
import math
import re

YES = ("YES", "NO")


# ---------------------------------------------------------------- разбор входа

def last_block(text: str, lines: int = 6) -> str:
    """Последние содержательные строки: там обычно сам вопрос."""
    rows = [l.strip() for l in text.splitlines() if l.strip()]
    skip = re.compile(r"^(>|answer|ответ|your answer|input|ввод)\s*[:\-]?$", re.I)
    rows = [l for l in rows if not skip.match(l)]
    return "\n".join(rows[-lines:])


def nums(text: str):
    out = []
    # «раунд 3», «wave 12/100», «попытка 2» — это не данные задачи
    text = re.sub(r"(?i)\b(round|раунд|wave|волна|попытка|attempt|level|уровень)"
                  r"\s*[:#№-]?\s*\d+(?:\s*/\s*\d+)?", " ", text)
    for m in re.finditer(r"-?\d+(?:[.,]\d+)?", text):
        s = m.group().replace(",", ".")
        try:
            out.append(int(s) if re.fullmatch(r"-?\d+", s) else float(s))
        except ValueError:
            pass
    return out


def quoted(text: str):
    m = re.search(r"['\"«`]([^'\"»`]{1,300})['\"»`]", text)
    return m.group(1) if m else None


def _fmt(value) -> str:
    if isinstance(value, float):
        if value.is_integer():
            return str(int(value))
        return ("%.6f" % value).rstrip("0").rstrip(".")
    return str(value)


# ---------------------------------------------------------------- арифметика

_TOKEN = re.compile(r"\s*(\d+(?:\.\d+)?|[()+\-*/%^])")


def eval_expr(expr: str, trunc: bool = False):
    """Безопасный калькулятор: + - * / % ^ и скобки, приоритеты как в C."""
    expr = expr.replace("×", "*").replace("÷", "/").replace("**", "^")
    tokens, pos = [], 0
    while pos < len(expr):
        m = _TOKEN.match(expr, pos)
        if not m:
            break
        tokens.append(m.group(1))
        pos = m.end()
    if not tokens:
        return None

    prec = {"+": 1, "-": 1, "*": 2, "/": 2, "%": 2, "^": 3}
    right = {"^"}
    out, ops = [], []

    def apply(op):
        if len(out) < 2:
            raise ValueError("мало операндов")
        b, a = out.pop(), out.pop()
        if op == "+":
            out.append(a + b)
        elif op == "-":
            out.append(a - b)
        elif op == "*":
            out.append(a * b)
        elif op == "/":
            out.append(a / b)
        elif op == "%":
            out.append(a % b)
        elif op == "^":
            out.append(a ** b)

    expect_operand = True
    for t in tokens:
        if t == "(":
            ops.append(t)
            expect_operand = True
        elif t == ")":
            while ops and ops[-1] != "(":
                apply(ops.pop())
            if ops:
                ops.pop()
            expect_operand = False
        elif t in prec:
            if expect_operand and t == "-":
                out.append(0)
            while (ops and ops[-1] != "(" and
                   (prec[ops[-1]] > prec[t] or
                    (prec[ops[-1]] == prec[t] and t not in right))):
                apply(ops.pop())
            ops.append(t)
            expect_operand = True
        else:
            out.append(float(t))
            expect_operand = False
    while ops:
        apply(ops.pop())
    if len(out) != 1:
        return None
    val = out[0]
    return int(val) if trunc or float(val).is_integer() else val


def solve_expression(q):
    text = q["text"]
    trunc = bool(re.search(r"round\s+to\s+zero|цел(ую|ая) часть|отбрось дроб|"
                           r"truncate|округл(и|ите)? вниз", text, re.I))
    best = None
    for m in re.finditer(r"[0-9()\s.+\-*/%^×÷]{3,}", text):
        expr = m.group().strip()
        if not re.search(r"\d\s*[-+*/%^]\s*\d", expr):
            continue
        # даты и версии — не арифметика
        if re.search(r"\d{4}-\d{2}-\d{2}|\d{1,2}[./]\d{1,2}[./]\d{2,4}", expr):
            continue
        try:
            val = eval_expr(expr, trunc)
        except Exception:
            continue
        if val is None:
            continue
        if best is None or len(expr) > len(best[0]):
            best = (expr, val)
    return _fmt(best[1]) if best else None


def solve_missing_operator(q):
    m = re.search(r"(-?\d+(?:[.,]\d+)?)\s*\?\s*(-?\d+(?:[.,]\d+)?)\s*=\s*"
                  r"(-?\d+(?:[.,]\d+)?)", q["text"])
    if not m:
        return None
    a, b, c = (float(x.replace(",", ".")) for x in m.groups())
    for op, val in (("+", a + b), ("-", a - b), ("*", a * b)):
        if abs(val - c) < 1e-6:
            return op
    if b and abs(a / b - c) < 1e-6:
        return "/"
    if b and abs(a % b - c) < 1e-6:
        return "%"
    return None


# ---------------------------------------------------------------- числа

def is_prime(n: int) -> bool:
    if n < 2:
        return False
    if n % 2 == 0:
        return n == 2
    d = 3
    while d * d <= n:
        if n % d == 0:
            return False
        d += 2
    return True


def next_prime(n: int) -> int:
    n = max(2, n + 1)
    while not is_prime(n):
        n += 1
    return n


def factorize(n: int):
    out, d = [], 2
    while d * d <= n:
        while n % d == 0:
            out.append(d)
            n //= d
        d += 1 if d == 2 else 2
    if n > 1:
        out.append(n)
    return out


def divisors(n: int):
    out = []
    for d in range(1, int(abs(n) ** 0.5) + 1):
        if n % d == 0:
            out.append(d)
            if d * d != n:
                out.append(n // d)
    return sorted(out)


def solve_prime(q):
    text = q["text"].lower()
    n = nums(q["text"])
    if not n:
        return None
    n = int(abs(n[0]))
    if re.search(r"следующ|next", text):
        return str(next_prime(n))
    if re.search(r"\d+\s*(?:-?й|-?ый|-?ой)?\s*(?:по\s*сч[её]ту\s*)?прост", text) and \
            re.search(r"(?:ое|ый|й)\s+прост", text):
        cnt, cur = 0, 1
        while cnt < n:
            cur += 1
            if is_prime(cur):
                cnt += 1
        return str(cur)
    if re.search(r"между|between|в диапазоне|from|до", text) and len(nums(q["text"])) >= 2:
        a, b = sorted(int(x) for x in nums(q["text"])[:2])
        if re.search(r"колич|count|сколько", text):
            return str(sum(is_prime(x) for x in range(a, b + 1)))
        return str(sum(1 for x in range(a, b + 1) if is_prime(x)))
    if re.search(r"множител|factor", text):
        return " ".join(map(str, factorize(n)))
    if re.search(r"является ли|is\s+\d+\s+prime|простое ли", text):
        return "YES" if is_prime(n) else "NO"
    return "YES" if is_prime(n) else "NO"


def solve_divisors(q):
    n = nums(q["text"])
    if not n:
        return None
    n = int(abs(n[0]))
    ds = divisors(n)
    low = q["text"].lower()
    if re.search(r"сумм|sum", low):
        return str(sum(ds))
    if re.search(r"наибольш|largest|max", low):
        return str(ds[-1])
    if re.search(r"список|list|все", low):
        return " ".join(map(str, ds))
    return str(len(ds))


def solve_gcd(q):
    n = [int(x) for x in nums(q["text"]) if float(x).is_integer()]
    if len(n) < 2:
        return None
    low = q["text"].lower()
    if re.search(r"нок|lcm", low):
        v = 1
        for x in n:
            v = v * x // math.gcd(v, x)
        return str(v)
    g = 0
    for x in n:
        g = math.gcd(g, x)
    return str(g)


def solve_coprime(q):
    n = [int(x) for x in nums(q["text"]) if float(x).is_integer()]
    if len(n) < 2:
        return None
    return "YES" if math.gcd(n[0], n[1]) == 1 else "NO"


def solve_factorial(q):
    n = nums(q["text"])
    if not n:
        return None
    k = int(n[0])
    if not 0 <= k <= 5000:
        return None
    return str(math.factorial(k))


def solve_fibonacci(q):
    n = nums(q["text"])
    if not n:
        return None
    k = int(n[0])
    if not 0 <= k <= 100000:
        return None
    a, b = 0, 1
    for _ in range(k):
        a, b = b, a + b
    return str(a)


def solve_digits(q):
    n = nums(q["text"])
    if not n:
        return None
    s = str(abs(int(n[0])))
    low = q["text"].lower()
    if re.search(r"переверн|reverse", low):
        return s[::-1]
    if re.search(r"палиндром|palindrome", low):
        return "YES" if s == s[::-1] else "NO"
    if re.search(r"колич|count|сколько", low):
        d = re.search(r"цифр[а-я]*\s*(\d)", low)
        return str(s.count(d.group(1))) if d else str(len(s))
    if re.search(r"корень|root", low):
        while len(s) > 1:
            s = str(sum(int(c) for c in s))
        return s
    return str(sum(int(c) for c in s))


# ---------------------------------------------------------------- строки

_VOW = "aeiouyAEIOUYаеёиоуыэюяАЕЁИОУЫЭЮЯ"


def solve_string(q):
    text = q["text"]
    low = text.lower()
    s = quoted(text)
    if s is None:
        m = re.search(r"(?:слово|строк[ау]|word|string)\s*[:=]?\s*([^\s,.;:!?]{2,})", text, re.I)
        s = m.group(1) if m else None
    if s is None:
        return None
    if re.search(r"переверн|reverse|задом", low):
        return s[::-1]
    if re.search(r"палиндром|palindrome", low):
        return "YES" if s.lower() == s[::-1].lower() else "NO"
    if re.search(r"гласн|vowel", low) and re.search(r"согласн|consonant", low):
        v = sum(c in _VOW for c in s)
        c = sum(ch.isalpha() and ch not in _VOW for ch in s)
        return f"{v} {c}"
    if re.search(r"гласн|vowel", low):
        return str(sum(ch in _VOW for ch in s))
    if re.search(r"согласн|consonant", low):
        return str(sum(ch.isalpha() and ch not in _VOW for ch in s))
    if re.search(r"слов|words", low):
        return str(len(re.findall(r"[\w\-]+", s)))
    if re.search(r"длин|length|символ", low):
        return str(len(s))
    if re.search(r"заглавн|upper", low):
        return s.upper()
    if re.search(r"строчн|lower", low):
        return s.lower()
    if re.search(r"уникальн|unique", low):
        return str(len(set(s)))
    return None


def solve_count_substring(q):
    text = q["text"]
    pairs = re.findall(r"['\"«`]([^'\"»`]{1,100})['\"»`]", text)
    if len(pairs) < 2:
        return None
    needle, hay = pairs[0], pairs[1]
    if re.search(r"сколько раз|how many times|occurrences|встреча", text, re.I):
        return str(hay.count(needle))
    return None


def solve_replace(q):
    text = q["text"]
    pairs = re.findall(r"['\"«`]([^'\"»`]{1,100})['\"»`]", text)
    if len(pairs) < 3:
        return None
    return pairs[2].replace(pairs[0], pairs[1])


# ---------------------------------------------------------------- массивы

def solve_numbers_block(q):
    text = q["text"]
    low = text.lower()
    n = nums(text)
    if not n:
        return None
    ints = [int(x) for x in n if float(x).is_integer()]
    if re.search(r"средн|average|mean", low):
        return _fmt(sum(n) / len(n))
    if re.search(r"наибольш|максим|maximum|\bmax\b", low):
        return str(max(n))
    if re.search(r"наименьш|миним|minimum|\bmin\b", low):
        return str(min(n))
    if re.search(r"произвед|product|multip", low):
        p = 1
        for x in n:
            p *= x
        return _fmt(p)
    if re.search(r"колич|count|сколько", low) and re.search(r"чис|number", low):
        return str(len(n))
    if re.search(r"сумм|\bsum\b|итог|total", low):
        return _fmt(sum(n))
    if re.search(r"отсортир|sort", low):
        rev = bool(re.search(r"убыв|desc|обратн", low))
        return " ".join(str(x) for x in sorted(ints or n, reverse=rev))
    if re.search(r"медиан|median", low):
        s = sorted(n)
        m = len(s) // 2
        return _fmt(s[m] if len(s) % 2 else (s[m - 1] + s[m]) / 2)
    return None


# ---------------------------------------------------------------- последовательности

def solve_sequence(q):
    text = q["text"]
    if not re.search(r"продолж|следующ|next|последовательн|sequence|ряд", text, re.I):
        return None
    m = re.findall(r"-?\d+", text)
    if len(m) < 3:
        return None
    seq = [int(x) for x in m]
    tail = seq[-8:] if len(seq) > 8 else seq
    diffs = [tail[i + 1] - tail[i] for i in range(len(tail) - 1)]
    if len(set(diffs)) == 1:
        return str(tail[-1] + diffs[0])
    if all(d and tail[i + 1] % tail[i] == 0 for i, d in enumerate(diffs)):
        ratios = {tail[i + 1] // tail[i] for i in range(len(tail) - 1)}
        if len(ratios) == 1:
            return str(tail[-1] * ratios.pop())
    if len(tail) >= 3 and all(tail[-i] == tail[-i - 1] + tail[-i - 2]
                              for i in (1, 2)):
        return str(tail[-1] + tail[-2])
    second = [diffs[i + 1] - diffs[i] for i in range(len(diffs) - 1)]
    if len(set(second)) == 1:
        return str(tail[-1] + diffs[-1] + second[0])
    return None


# ---------------------------------------------------------------- основания/биты

def solve_base(q):
    text = q["text"]
    low = text.lower()
    n = nums(text)
    if not n:
        return None
    if re.search(r"в двоичн|to binary|binary", low):
        return format(int(n[0]), "b")
    if re.search(r"в шестнадцат|to hex|hexadecimal", low):
        return format(int(n[0]), "x")
    if re.search(r"в восьмерич|to octal|octal", low):
        return format(int(n[0]), "o")
    if re.search(r"из двоичн|from binary", low):
        return str(int(str(int(n[0])), 2))
    if re.search(r"из шестнадцат|from hex", low):
        return str(int(str(n[0]), 16))
    return None


def solve_power_mod(q):
    text = q["text"].lower()
    m = re.search(r"(\d+)\s*(?:\^|в степени|\*\*)\s*(\d+)\s*(?:mod|по модулю|modulo)\s*(\d+)", text)
    if m:
        return str(pow(int(m.group(1)), int(m.group(2)), int(m.group(3))))
    m = re.search(r"(\d+)\s*(?:\^|в степени|\*\*)\s*(\d+)", text)
    if m and re.search(r"степен|power|\^|\*\*", text):
        return str(int(m.group(1)) ** int(m.group(2)))
    return None


# ---------------------------------------------------------------- даты

_WD = ["понедельник", "вторник", "среда", "четверг", "пятница", "суббота",
       "воскресенье"]


def _parse_date(s: str):
    s = s.strip()
    for fmt in ("%d.%m.%Y", "%Y-%m-%d", "%d/%m/%Y", "%m/%d/%Y", "%Y.%m.%d"):
        try:
            return _dt.datetime.strptime(s, fmt).date()
        except ValueError:
            continue
    return None


def solve_date(q):
    text = q["text"]
    days = re.findall(r"\d{1,2}[./]\d{1,2}[./]\d{2,4}|\d{4}-\d{2}-\d{2}", text)
    if not days:
        return None
    d1 = _parse_date(days[0])
    if not d1:
        return None
    if len(days) >= 2:
        d2 = _parse_date(days[1])
        if d2:
            return str(abs((d2 - d1).days))
    if re.search(r"день недели|weekday|day of week|какой день", text, re.I):
        return _WD[d1.weekday()]
    return None


# ---------------------------------------------------------------- кодировки

def solve_encoding(q):
    text = q["text"]
    low = text.lower()
    import base64
    if re.search(r"base64", low):
        if re.search(r"декодир|decode|расшифр", low):
            for tok in re.findall(r"[A-Za-z0-9+/=]{8,}", text):
                try:
                    out = base64.b64decode(tok + "=" * (-len(tok) % 4)).decode()
                    if out.isprintable():
                        return out
                except Exception:
                    continue
        m = quoted(text)
        if m:
            return base64.b64encode(m.encode()).decode()
    if re.search(r"\bhex\b|шестнадцатерич", low):
        if re.search(r"декодир|decode", low):
            for tok in re.findall(r"(?:[0-9a-fA-F]{2}){4,}", text):
                try:
                    out = bytes.fromhex(tok).decode()
                    if out.isprintable():
                        return out
                except Exception:
                    continue
        m = quoted(text)
        if m:
            return m.encode().hex()
    return None


# ---------------------------------------------------------------- логика

def solve_logic(q):
    text = q["text"]
    if not re.search(r"\b(true|false|истин|ложн|and|or|not|и\b|или\b|не\b)", text, re.I):
        return None
    expr = text.lower()
    expr = re.sub(r"\bистин\w*\b", "True", expr)
    expr = re.sub(r"\bложь\b|\bложн\w*\b", "False", expr)
    expr = expr.replace(" and ", " and ").replace(" or ", " or ")
    expr = re.sub(r"\bи\b", " and ", expr)
    expr = re.sub(r"\bили\b", " or ", expr)
    expr = re.sub(r"\bне\b", " not ", expr)
    expr = re.sub(r"\btrue\b", "True", expr)
    expr = re.sub(r"\bfalse\b", "False", expr)
    best = ""
    for m in re.finditer(r"(?:True|False|and|or|not|\(|\)|\s)+", expr):
        chunk = m.group().strip()
        if ("True" in chunk or "False" in chunk) and len(chunk) > len(best):
            best = chunk
    if not best:
        return None
    try:
        val = eval(best, {"__builtins__": {}}, {})  # noqa: S307
    except Exception:
        return None
    return "YES" if val else "NO"


# ---------------------------------------------------------------- OCR

def _tesseract_cmd():
    import os
    import shutil
    for cand in (os.environ.get("TESSERACT_CMD"),
                 shutil.which("tesseract"),
                 r"C:\Program Files\Tesseract-OCR\tesseract.exe",
                 r"C:\Program Files (x86)\Tesseract-OCR\tesseract.exe"):
        if cand and os.path.exists(cand):
            return cand
    return None


def solve_ocr(q):
    """Капча/картинка в base64 -> текст через pytesseract."""
    import base64
    import io
    import re as _re
    text = q["text"]
    if not _re.search(r"captcha|капча|\bocr\b|картинк|image|введи слово", text, _re.I):
        return None
    blob = None
    for m in _re.finditer(r"[A-Za-z0-9+/]{80,}={0,2}", text):
        try:
            raw = base64.b64decode(m.group() + "=" * (-len(m.group()) % 4))
        except Exception:
            continue
        if raw[:8] == b"\x89PNG\r\n\x1a\n" or raw[:3] == b"\xff\xd8\xff":
            blob = raw
            break
    if blob is None:
        return None
    cmd = _tesseract_cmd()
    if not cmd:
        return None
    try:
        import pytesseract
        from PIL import Image, ImageOps
    except Exception:
        return None
    pytesseract.pytesseract.tesseract_cmd = cmd
    try:
        im = Image.open(io.BytesIO(blob)).convert("L")
        im = ImageOps.autocontrast(im)
        w, h = im.size
        if w < 300:
            im = im.resize((w * 3, h * 3))
        im = im.point(lambda x: 0 if x < 140 else 255)
        out = pytesseract.image_to_string(
            im, config="--psm 7 -c tessedit_char_whitelist="
                       "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
    except Exception:
        return None
    out = "".join(ch for ch in out if ch.isalnum())
    return out or None


# ---------------------------------------------------------------- реестр

def _kw(pattern):
    return re.compile(pattern, re.I)


SOLVERS = [
    # (имя, ключевые слова, функция)
    ("missing_operator", _kw(r"\?\s*=|=.*\?|какой оператор|which operator|пропущен"), solve_missing_operator),
    ("date", _kw(r"день недели|weekday|day of week|какой день|дат[аеу]|\bdate\b|дней"), solve_date),
    ("power_mod", _kw(r"степен|power|\^|mod|модул"), solve_power_mod),
    ("base", _kw(r"двоичн|binary|шестнадцат|hex|восьмерич|octal|систем[аеы] счислен"), solve_base),
    ("sequence", _kw(r"продолж|следующ|next|последовательн|sequence"), solve_sequence),
    ("coprime", _kw(r"взаимно\s*прост|coprime"), solve_coprime),
    ("factorial", _kw(r"факториал|factorial"), solve_factorial),
    ("prime", _kw(r"\bпрост(ое|ым|ые|ых|ого|ая|ой|ыми|ому)\b|(?<!co)\bprime\b|"
                  r"простые\s+множител|prime\s+factors"), solve_prime),
    ("divisors", _kw(r"делител|divisor"), solve_divisors),
    ("gcd", _kw(r"нод|нок|gcd|lcm"), solve_gcd),
    ("fibonacci", _kw(r"фибоначч|fibonacci"), solve_fibonacci),
    ("digits", _kw(r"цифр|digit|переверн|reverse|палиндром|palindrome"), solve_digits),
    ("encoding", _kw(r"base64|\bhex\b|закодир|encode|декодир|decode"), solve_encoding),
    ("ocr", _kw(r"captcha|капча|\bocr\b|картинк|image"), solve_ocr),
    ("replace", _kw(r"замени|replace"), solve_replace),
    ("count_substring", _kw(r"сколько раз|how many times|occurrences|встреча"), solve_count_substring),
    ("logic", _kw(r"\btrue\b|\bfalse\b|истин|ложь|ложн|\band\b|\bor\b|\bnot\b"), solve_logic),
    ("string", _kw(r"гласн|vowel|согласн|consonant|переверн|reverse|"
                   r"палиндром|palindrome|длин|length|слов|words|заглавн|upper|"
                   r"строчн|lower|уникальн|unique"), solve_string),
    ("numbers", _kw(r"сумм|\bsum\b|произвед|product|средн|average|"
                    r"наибольш|максим|maximum|\bmax\b|наименьш|миним|minimum|\bmin\b|"
                    r"отсортир|sort|медиан|median|колич|count"), solve_numbers_block),
    ("expression", _kw(r"[-+*/%^]|вычисл|посчитай|calculate|реши"), solve_expression),
]


def candidates(text: str):
    """Упорядоченный список (имя, ответ) для текста вопроса."""
    block = last_block(text)
    q = {"text": block, "raw": text}
    out, seen = [], set()
    for name, kw, fn in SOLVERS:
        if not kw.search(block) and not kw.search(text[-500:]):
            continue
        try:
            ans = fn(q)
        except Exception:
            ans = None
        if ans is None or str(ans).strip() == "":
            continue
        ans = str(ans).strip()
        if ans not in seen:
            seen.add(ans)
            out.append((name, ans))
    # если ничего по ключевым словам — пробуем «по форме»
    if not out:
        for name, fn in (("expression", solve_expression),
                         ("missing_operator", solve_missing_operator),
                         ("numbers", solve_numbers_block)):
            try:
                ans = fn(q)
            except Exception:
                ans = None
            if ans is not None and str(ans).strip():
                ans = str(ans).strip()
                if ans not in seen:
                    seen.add(ans)
                    out.append((name, ans))
    return out


def solve(text: str):
    """Самый вероятный ответ или None."""
    cand = candidates(text)
    return cand[0][1] if cand else None


if __name__ == "__main__":
    import sys
    sample = " ".join(sys.argv[1:]) or "2 + 2 * 2"
    print("вопрос:", last_block(sample))
    for name, ans in candidates(sample):
        print(f"  {name:18} -> {ans}")


# ---------------------------------------------------------------- сетки

def parse_grid(text: str):
    """Найти в тексте прямоугольную сетку из символов; вернуть список строк."""
    lines = [l.rstrip() for l in text.splitlines() if l.strip()]
    groups, cur = [], []
    for line in lines:
        compact = re.sub(r"\s+", "", line)
        if not compact:
            continue
        if cur and len(compact) != len(cur[-1]):
            if len(cur) >= 3 and len(cur[0]) >= 3:
                groups.append(cur)
            cur = []
        cur.append(compact)
    if len(cur) >= 3 and len(cur[0]) >= 3:
        groups.append(cur)
    for g in groups:
        chars = set("".join(g))
        if len(chars) >= 2 and ({"S", "E"} & chars or "#" in chars):
            return g
    return None


def solve_grid_path(text: str):
    """BFS от S до E; вернуть путь буквами WASD (пусто, если нет сетки)."""
    grid = parse_grid(text)
    if not grid:
        return None
    h, w = len(grid), len(grid[0])
    start = end = None
    for y, row in enumerate(grid):
        for x, ch in enumerate(row):
            if ch in "Ss":
                start = (x, y)
            elif ch in "Ee":
                end = (x, y)
    if not start:
        return None
    from collections import deque
    walls = set("#█▓▒")
    q = deque([start])
    prev = {start: None}
    moves = {(1, 0): "D", (-1, 0): "A", (0, 1): "S", (0, -1): "W"}
    goal = end
    while q:
        x, y = q.popleft()
        if goal and (x, y) == goal:
            break
        for (dx, dy), key in moves.items():
            nx, ny = x + dx, y + dy
            if 0 <= nx < w and 0 <= ny < h and (nx, ny) not in prev \
                    and grid[ny][nx] not in walls:
                prev[(nx, ny)] = ((x, y), key)
                q.append((nx, ny))
    if not goal:
        # без E — просто показать достижимость
        return ""
    if goal not in prev:
        return None
    path, node = [], goal
    while prev.get(node):
        (px, py), key = prev[node]
        path.append(key)
        node = (px, py)
    return "".join(reversed(path))
