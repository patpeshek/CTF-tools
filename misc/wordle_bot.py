#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
wordle_bot.py — решатель Wordle (рус/англ) для сервисов «угадай слово за N секунд».

  # офлайн-проверка решателя: сколько попыток нужно
  python wordle_bot.py dry --target серия --words F:\\dev\\wordlists\\russian5.txt

  # игра по сети
  python wordle_bot.py play --connect h:1337 --words F:\\dev\\wordlists\\russian5.txt

  # не знаем протокол: бот печатает подсказку, вы вводите ответ сервиса
  python wordle_bot.py assist --words F:\\dev\\wordlists\\russian5.txt

Формат ответа сервиса распознаётся сам:
  • эмодзи 🟩🟨⬛ (и 🟢🟡⚫, ✅💛❌);
  • ascii-маркеры G/Y/B, +/−/., 2/1/0;
  • слова «зелёный/жёлтый/серый»;
  • «быки N коровы M» (тогда позиции не нужны, считается по количеству);
  • JSON с полем feedback/result/marks.

Стратегия: фильтр по правилам Wordle (с учётом повторных букв), выбор слова по
сумме частот букв; первый ход — самое «буквенное» слово словаря.
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
import json
import os
import re
import socket
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import common  # noqa: E402
import formats as fmt  # noqa: E402

GREEN = set("🟩🟢✅💚🟏")
YELLOW = set("🟨🟡💛⚠️")
GRAY = set("⬛⚫⬜🔳🔲❌⛔🟥🔴")


def load_words(path: str, length: int) -> list[str]:
    words = []
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            w = line.strip().lower().replace("ё", "е")
            if len(w) == length and w.isalpha():
                words.append(w)
    # уникальные, стабильный порядок
    seen, out = set(), []
    for w in words:
        if w not in seen:
            seen.add(w)
            out.append(w)
    return out


def letter_freq(words: list[str]) -> dict[str, float]:
    freq: dict[str, float] = {}
    for w in words:
        for ch in set(w):
            freq[ch] = freq.get(ch, 0) + 1
    return freq


def feedback(guess: str, target: str) -> list[str]:
    """Классические правила Wordle: сначала точные, потом «есть в слове»."""
    n = len(guess)
    res = ["b"] * n
    counts: dict[str, int] = {}
    for ch in target:
        counts[ch] = counts.get(ch, 0) + 1
    for i, (g, t) in enumerate(zip(guess, target)):
        if g == t:
            res[i] = "g"
            counts[g] -= 1
    for i, g in enumerate(guess):
        if res[i] == "b" and counts.get(g, 0) > 0:
            res[i] = "y"
            counts[g] -= 1
    return res


def consistent(word: str, guess: str, fb: list[str]) -> bool:
    return feedback(guess, word) == fb


def score_word(word: str, freq: dict[str, float]) -> float:
    return sum(freq.get(ch, 0) for ch in set(word))


def entropy_choice(guesses: list[str], targets: list[str], budget: float = 1.5):
    """Слово, которое сильнее всего делит оставшиеся варианты."""
    import math
    import time

    started = time.monotonic()
    best, best_h = None, -1.0
    for g in guesses:
        dist: dict[tuple, int] = {}
        for t in targets:
            key = tuple(feedback(g, t))
            dist[key] = dist.get(key, 0) + 1
        total = len(targets)
        h = 0.0
        for cnt in dist.values():
            p = cnt / total
            h -= p * math.log2(p)
        if h > best_h:
            best, best_h = g, h
        if time.monotonic() - started > budget:
            break
    return best


def best_opener(words: list[str], freq: dict[str, float]) -> str | None:
    """Первый ход: энтропия по топ-400 слов на выборке из словаря."""
    if not words:
        return None
    guesses = sorted(words, key=lambda w: score_word(w, freq), reverse=True)[:400]
    step = max(1, len(words) // 1500)
    targets = words[::step][:1500]
    return entropy_choice(guesses, targets, budget=2.0)


def pick_guess(cands: list[str], freq: dict[str, float], tried: set[str],
               opener: str | None = None, all_words: list[str] | None = None) -> str | None:
    pool = [w for w in cands if w not in tried] or cands
    if not pool:
        return None
    if len(pool) <= 2:
        return pool[0]
    if not tried and opener:
        return opener
    # эндшпиль: зондируем словами вне кандидатов, чтобы различить окончания
    if all_words and len(pool) <= 6 and len(tried) >= 2:
        probe = sorted(all_words, key=lambda w: score_word(w, freq), reverse=True)[:800]
        guess = entropy_choice([w for w in probe if w not in tried], pool, budget=0.8)
        if guess:
            return guess
    if len(pool) <= 700:
        return entropy_choice(pool, pool, budget=1.2)
    guesses = sorted(pool, key=lambda w: score_word(w, freq), reverse=True)[:300]
    step = max(1, len(pool) // 1200)
    targets = pool[::step][:1200]
    return entropy_choice(guesses, targets, budget=1.2)


CYR_DEFAULT = {
    "Г": "g", "З": "g", "Б": "g", "В": "g",     # горит/зелёный/бык/верно
    "Ж": "y", "К": "y", "П": "y",               # жёлтый/корова/присутствует
    "С": "b", "Н": "b", "О": "b", "Х": "b",     # серый/нет/отсутствует
}


def _cyr_map() -> dict[str, str]:
    m = dict(CYR_DEFAULT)
    for key, val in (("WORDLE_GREEN", "g"), ("WORDLE_YELLOW", "y"),
                     ("WORDLE_GRAY", "b")):
        for ch in os.environ.get(key, ""):
            m[ch.upper()] = val
    return m


def _cyr_vec(tokens, n, mapping):
    if len(tokens) != n:
        return None
    out = []
    for t in tokens:
        up = t.upper()
        if len(up) != 1 or up not in mapping:
            return None
        out.append(mapping[up])
    return out


def parse_feedback(text: str, n: int):
    """Вернуть ('vec', [g/y/b...]) или ('count', быки, коровы) или None."""
    mapping = _cyr_map()
    # буквенные маркеры под словом: «Г Ж С С С» или «ГЖССС» (русская разметка)
    lines_all = [l.strip() for l in text.splitlines() if l.strip()]
    for i in range(len(lines_all) - 1, -1, -1):
        line = lines_all[i]
        prev = lines_all[i - 1] if i else ""
        word_above = len(prev) == n and prev.isalpha()
        toks = [t for t in re.split(r"[\s|,]+", line) if t]
        if len(toks) == n and all(len(t) == 1 for t in toks):
            vec = _cyr_vec(toks, n, mapping)
            if vec and (word_above or n <= 2):
                return ("vec", vec)
        if toks and len(toks[0]) == n and len(toks) == n + 1:
            vec = _cyr_vec(toks[1:], n, mapping)
            if vec:
                return ("vec", vec)
        compact = re.sub(r"[\s|,]+", "", line)
        if word_above and len(compact) == n and compact.isalpha():
            vec = _cyr_vec(list(compact), n, mapping)
            if vec:
                return ("vec", vec)

    # ANSI-цвета (терминальные клоны Wordle красят фон)
    ansi = re.findall(r"\x1b\[([0-9;]*)m", text)
    if ansi:
        stripped = re.sub(r"\x1b\[[0-9;]*m", "", text)
        # ищем строку из n непробельных символов и цвета перед ними
        for line in stripped.splitlines():
            chunk = re.sub(r"\s", "", line)
            if len(chunk) != n or not chunk.isalpha():
                continue
            # цвета берём из исходной строки с ANSI
            for raw in text.splitlines():
                if re.sub(r"\x1b\[[0-9;]*m", "", raw).strip() != line.strip():
                    continue
                colors = []
                for m in re.finditer(r"\x1b\[([0-9;]*)m\s*\S", raw):
                    codes = m.group(1)
                    if "42" in codes or "32" in codes:
                        colors.append("g")
                    elif "43" in codes or "33" in codes:
                        colors.append("y")
                    elif "40" in codes or "47" in codes or "90" in codes:
                        colors.append("b")
                if len(colors) == n:
                    return ("vec", colors)

    # HTML/markdown-раскраска
    low_html = text.lower()
    if "color:" in low_html or "<span" in low_html:
        row = re.findall(r"<span[^>]*color:\s*(green|#0f0|#00ff00|yellow|#ff0|"
                         r"#ffff00|gray|grey|#808080)[^>]*>([^<])</span>", low_html)
        if len(row) == n:
            vec = []
            for color, _ch in row:
                if "green" in color or "#0f0" in color or "#00ff00" in color:
                    vec.append("g")
                elif "yellow" in color or "#ff0" in color:
                    vec.append("y")
                else:
                    vec.append("b")
            return ("vec", vec)

    # «слово угадано целиком»
    if re.search(r"правильн|верно|угадал|correct|you win|победа", text, re.I):
        if not re.search(r"не\s*правильн|incorrect|неверн", text, re.I):
            return ("vec", ["g"] * n)

    # JSON
    for m in re.finditer(r"\{[^{}]{5,400}\}", text):
        try:
            data = json.loads(m.group())
        except Exception:
            continue
        for key in ("feedback", "result", "marks", "colors", "state"):
            val = data.get(key)
            if isinstance(val, list) and len(val) == n:
                vec = []
                for item in val:
                    s = str(item).lower()
                    if s in ("g", "green", "correct", "1", "true"):
                        vec.append("g")
                    elif s in ("y", "yellow", "present", "2"):
                        vec.append("y")
                    else:
                        vec.append("b")
                return ("vec", vec)

    lines = [l for l in text.splitlines() if l.strip()]
    # эмодзи-строка (последняя)
    for line in reversed(lines):
        marks = [ch for ch in line if ch in GREEN | YELLOW | GRAY]
        if len(marks) == n:
            return ("vec", ["g" if c in GREEN else "y" if c in YELLOW else "b"
                            for c in marks])
    # ascii-маркеры
    for line in reversed(lines):
        s = line.strip()
        compact = re.sub(r"[\s|,/]+", "", s)
        if len(compact) == n and set(compact.lower()) <= set("gyb+-.x_"):
            vec = []
            for ch in compact.lower():
                if ch in "g+":
                    vec.append("g")
                elif ch in "y.":
                    vec.append("y")
                else:
                    vec.append("b")
            return ("vec", vec)
    # словами (нужно минимум два разных цвета, иначе «серия» = «серый»)
    for line in reversed(lines):
        low = line.lower()
        colors = sum(bool(re.search(p, low)) for p in
                     (r"зел[её]н", r"ж[её]лт", r"сер|ч[её]рн"))
        if colors >= 2:
            return None  # цветовая строка без позиций — не рискуем
    # быки и коровы
    bulls = re.search(r"бык\w*\s*[:=]?\s*(\d+)", text, re.I)
    cows = re.search(r"коров\w*\s*[:=]?\s*(\d+)", text, re.I)
    if bulls and cows:
        return ("count", int(bulls.group(1)), int(cows.group(1)))

    # произвольные символы под словом: «1 2 0 0 2», «✓ ~ ✗» и т.п.
    for i in range(len(lines_all) - 1, -1, -1):
        line = lines_all[i]
        prev = lines_all[i - 1] if i else ""
        if not (len(prev) == n and prev.isalpha()):
            continue
        toks = [t for t in re.split(r"[\s|,]+", line) if t]
        if len(toks) == n and all(len(t) == 1 for t in toks):
            return ("raw", [t.upper() for t in toks])
    return None


def count_ok(word: str, guess: str, bulls: int, cows: int) -> bool:
    exact = sum(1 for a, b in zip(guess, word) if a == b)
    if exact != bulls:
        return False
    common_letters = 0
    w1, w2 = list(guess), list(word)
    for ch in set(guess):
        common_letters += min(w1.count(ch), w2.count(ch))
    return common_letters - exact == cows


def solve_dry(words: list[str], target: str, max_guesses: int, freq,
              opener=None, quiet=False):
    cands = list(words)
    tried: set[str] = set()
    log = []
    for attempt in range(1, max_guesses + 1):
        guess = pick_guess(cands, freq, tried, opener, words)
        if not guess:
            break
        tried.add(guess)
        fb = feedback(guess, target)
        log.append((guess, "".join(fb)))
        if not quiet:
            print(f"  {attempt}: {guess}  {''.join(fb)}")
        if fb == ["g"] * len(guess):
            return attempt, log
        cands = [w for w in cands if consistent(w, guess, fb)]
        if not cands:
            break
    return None, log


class Conn:
    def __init__(self, sock):
        self.s = sock
        self.s.settimeout(0.3)

    def read_quiet(self, quiet_rounds=2, limit=65536):
        chunks, idle = [], 0
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
        return b"".join(chunks)

    def send(self, data: bytes):
        self.s.sendall(data)


def play_net(conn, words, freq, args, opener=None):
    n = args.length
    cands = list(words)
    tried: set[str] = set()
    pending = None
    solved = 0
    fails = 0
    attempts_this = 0
    grab = common.FlagGrabber()
    while True:
        data = conn.read_quiet()
        if not data:
            break
        text = data.decode("utf-8", "replace")
        if args.show_transcript:
            print(text.rstrip()[:1000])
        flags = grab.feed(data)
        if flags:
            print("[!!!] ФЛАГ:", " | ".join(flags))
            return 0

        if pending:
            parsed = parse_feedback(text, n)
            if parsed and parsed[0] == "raw":
                vec = fmt.resolve(parsed[1], text, interactive=sys.stdin.isatty())
                parsed = ("vec", vec) if vec else None
            if parsed and parsed[0] == "vec":
                fb = parsed[1]
                if fb == ["g"] * n:
                    solved += 1
                    print(f"[+] слово {pending} угадано (всего: {solved})")
                    cands = list(words)
                    tried = set()
                    pending = None
                    attempts_this = 0
                    continue
                before = len(cands)
                cands = [w for w in cands if consistent(w, pending, fb)]
                if not cands:
                    print(f"[!] кандидаты кончились на {pending}; сбрасываю словарь")
                    cands = list(words)
                print(f"[i] {pending} {''.join(fb)}: осталось {len(cands)} "
                      f"(было {before})")
                pending = None
                attempts_this = 0
            elif parsed and parsed[0] == "count":
                _, bulls, cows = parsed
                if bulls == n:
                    solved += 1
                    print(f"[+] слово {pending} угадано (всего: {solved})")
                    cands = list(words)
                    tried = set()
                    pending = None
                    attempts_this = 0
                    continue
                cands = [w for w in cands if count_ok(w, pending, bulls, cows)]
                print(f"[i] {pending} быки={bulls} коровы={cows}: осталось {len(cands)}")
                pending = None
                attempts_this = 0
            else:
                if args.dump:
                    with open(args.dump, "a", encoding="utf-8") as f:
                        f.write("NO-FEEDBACK:\n" + text + "\n---\n")
                print("[?] не понял формат ответа. Хвост:")
                print(text.rstrip()[-500:])
                print("[i] запусти `assist` и вводи ответ вручную, "
                      "или пришли этот хвост — добавим парсер")
                return 2

        if pending is None:
            if attempts_this >= args.max_guesses:
                print(f"[-] за {args.max_guesses} попыток слово не угадано")
                fails += 1
                cands = list(words)
                tried = set()
                attempts_this = 0
                continue
            guess = pick_guess(cands, freq, tried, opener, words)
            if not guess:
                print("[-] нечего предлагать")
                return 2
            tried.add(guess)
            pending = guess
            attempts_this += 1
            payload = (guess.upper() if args.upper else guess) + "\n"
            conn.send(payload.encode())
            print(f"[>] {guess}")

    print(f"[i] угадано: {solved}, провалов: {fails}")
    return 0 if solved else 1


def assist(words, freq, args, opener=None):
    print("[i] вводи ответ сервиса: 🟩🟨⬛, GYB, +/., «быки 1 коровы 2»; пусто = выход")
    cands = list(words)
    tried: set[str] = set()
    while True:
        guess = pick_guess(cands, freq, tried, opener, words)
        if not guess:
            print("[-] кандидатов нет")
            return
        print(f"\nпредлагаю: {guess}   (кандидатов: {len(cands)})")
        raw = input("ответ: ").strip()
        if not raw:
            return
        parsed = parse_feedback(raw, args.length)
        if not parsed:
            print("[?] не разобрал, попробуй ещё")
            continue
        tried.add(guess)
        if parsed[0] == "vec":
            fb = parsed[1]
            if fb == ["g"] * args.length:
                print("[+] угадали, начинаю заново")
                cands, tried = list(words), set()
                continue
            cands = [w for w in cands if consistent(w, guess, fb)]
        else:
            _, bulls, cows = parsed
            cands = [w for w in cands if count_ok(w, guess, bulls, cows)]
        print(f"    осталось: {len(cands)}")


def main():
    ap = argparse.ArgumentParser(epilog=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    for name in ("dry", "play", "assist"):
        p = sub.add_parser(name)
        p.add_argument("--words", default=r"F:\dev\wordlists\russian5.txt")
        p.add_argument("--length", type=int, default=5)
        p.add_argument("--max-guesses", type=int, default=6)
        p.add_argument("--upper", action="store_true", help="отправлять ЗАГЛАВНЫМИ")
        p.add_argument("--dump", help="куда писать нераспознанные ответы")
        p.add_argument("--show-transcript", action="store_true")
        if name == "dry":
            p.add_argument("--target", help="загаданное слово (иначе 100 случайных)")
            p.add_argument("--count", type=int, default=100)
        if name == "play":
            p.add_argument("--connect", help="host:port")
            p.add_argument("--local", help="локальная команда сервера")

    args = ap.parse_args()

    if not os.path.exists(args.words):
        print(f"[-] нет словаря: {args.words}")
        return 2
    words = load_words(args.words, args.length)
    if not words:
        print("[-] словарь пуст после фильтра по длине")
        return 2
    freq = letter_freq(words)
    print(f"[i] слов в словаре: {len(words)}")
    opener = best_opener(words, freq)
    print(f"[i] первый ход: {opener}")

    if args.cmd == "dry":
        if args.target:
            got, log = solve_dry(words, args.target.lower().replace("ё", "е"),
                                 args.max_guesses, freq, opener)
            if got:
                print(f"[+] угадано за {got} попыток")
            else:
                print("[-] не угадано")
            return 0 if got else 1
        import random
        random.seed(1)
        targets = random.sample(words, min(args.count, len(words)))
        ok, total, dist = 0, 0, {}
        for t in targets:
            got, _ = solve_dry(words, t, args.max_guesses, freq, opener, quiet=True)
            total += 1
            if got:
                ok += 1
                dist[got] = dist.get(got, 0) + 1
        print(f"[+] решено {ok}/{total} за <= {args.max_guesses} попыток")
        print("[i] распределение:", dict(sorted(dist.items())))
        return 0 if ok == total else 1

    if args.cmd == "assist":
        assist(words, freq, args, opener)
        return 0

    if bool(args.connect) == bool(args.local):
        print("[-] нужен ровно один из --connect или --local")
        return 2
    if args.local:
        sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__))), "pwn"))
        from oracle import ProcConn
        conn = ProcConn(args.local)
    else:
        host, _, port = args.connect.rpartition(":")
        conn = Conn(socket.create_connection((host, int(port)), timeout=3.0))
    return play_net(conn, words, freq, args, opener)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (FileNotFoundError, IsADirectoryError, PermissionError) as e:
        print(f"[-] не могу открыть: {getattr(e, 'filename', None) or e}")
    except BrokenPipeError:
        pass
    except KeyboardInterrupt:
        print("\n[-] прервано")
