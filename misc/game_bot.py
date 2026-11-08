#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
game_bot.py — общий бот для интерактивных сервисов: «что угодно» вместо
одного Wordle.

  # подключиться и попробовать самому понять, что происходит
  python game_bot.py --connect h:1337 --auto

  # записать протокол (если не понял) — потом написать плагин
  python game_bot.py --connect h:1337 --record game.log

  # свой плагин: файл с функцией move(text, state) -> str | None
  python game_bot.py --connect h:1337 --plugin my_strategy.py

  # гонка «жми q, следи за стаминой»
  python game_bot.py --connect h:1337 --keys q --stamina 30

  # без сети: посмотреть, что бот понял из текста
  python game_bot.py --analyze "5 букв, угадай слово: _ _ _ _ _"

Что умеет сам:
  • Q&A (числа, простые, взаимно простые, арифметика, гласные, слова,
    base64/hex, эмодзи) — стратегии из pwn/oracle.py, с закреплением после
    серии успешных раундов;
  • Wordle/«5 букв»: фильтр кандидатов + энтропийный выбор слова;
  • «нажми клавишу» / гонки: спам клавишей с паузой по стамине/HP;
  • флаг забирает сразу, как он появился в любом чанке, и ещё раз на EOF;
  • незнакомый формат — печатает, пишет в --record и не притворяется, что понял.

Плагин: `def move(text: str, state: dict) -> str | None`. Возврат — что
отправить в сервис (без \n). None = «не знаю, жди/стоп». В state есть
`last`, `round`, `history`, `flags`.
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
import importlib.util
import os
import re
import socket
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(ROOT, "pwn"))

import common  # noqa: E402
import oracle  # noqa: E402
import ppc_solvers  # noqa: E402
import wordle_bot as wb  # noqa: E402
import formats as fmt  # noqa: E402

GRID_CHARS = set(".#*xoXO01█▓░┌┐└┘│─+|-")


class Link:
    """TCP или локальный процесс; быстрое чтение, флаг — первым делом."""

    def __init__(self, sock=None, proc=None, idle=0.15):
        self.s = sock
        self.p = proc
        self.idle = idle
        self.log = []
        if sock is not None:
            sock.settimeout(idle)

    def read(self, quiet=2, limit=65536):
        chunks, idle = [], 0
        while idle < quiet and sum(map(len, chunks)) < limit:
            try:
                if self.s is not None:
                    d = self.s.recv(4096)
                else:
                    d = os.read(self.p.stdout.fileno(), 4096)
            except (socket.timeout, BlockingIOError, OSError):
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
        if isinstance(data, str):
            data = data.encode()
        try:
            if self.s is not None:
                self.s.sendall(data)
            else:
                self.p.stdin.write(data)
                self.p.stdin.flush()
        except OSError:
            return False
        self.log.append(("out", data))
        return True

    def close(self):
        try:
            if self.s is not None:
                self.s.close()
            else:
                self.p.stdin.close()
                self.p.terminate()
        except OSError:
            pass


def make_link(args) -> Link:
    if args.local:
        import shlex
        import subprocess
        p = subprocess.Popen(shlex.split(args.local, posix=False),
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, bufsize=0)
        os.set_blocking(p.stdout.fileno(), False)
        return Link(proc=p, idle=args.idle)
    host, _, port = args.connect.rpartition(":")
    if not host or not port.isdigit():
        raise SystemExit("--connect должен быть host:port")
    return Link(sock=socket.create_connection((host, int(port)), timeout=3.0),
                idle=args.idle)


def load_plugin(path):
    spec = importlib.util.spec_from_file_location("game_strategy", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    if not hasattr(mod, "move"):
        raise SystemExit(f"в {path} нет функции move(text, state)")
    return mod


def detect_lang(text: str) -> str:
    ru = len(re.findall(r"[а-яё]", text, re.I))
    en = len(re.findall(r"[a-z]", text, re.I))
    return "ru" if ru >= en else "en"


def detect_length(text: str) -> int | None:
    m = re.search(r"(\d)\s*(?:букв|letters?|символ|chars?)", text, re.I)
    if m:
        return int(m.group(1))
    # маска вида _ _ _ _ _ или ????? или -----
    for line in text.splitlines():
        for ch in "_?*":
            run = re.findall(re.escape(ch) + r"(?:\s*" + re.escape(ch) + r"){2,}", line)
            if run:
                return len(re.findall(re.escape(ch), run[0]))
    # ряд квадратов
    squares = [c for c in text if c in wb.GREEN | wb.YELLOW | wb.GRAY]
    if len(squares) >= 3:
        return len(squares) // max(1, len(text.splitlines()) - 1) if len(text.splitlines()) > 1 else len(squares)
    return None


def looks_like_wordle(text: str) -> bool:
    low = text.lower()
    if re.search(r"wordle|5\s*букв|пять букв|угадай слово|guess the word|"
                 r"загаданное слово", low):
        return True
    if re.search(r"[_?]{3,}", text) and re.search(r"букв|letter|слов", low):
        return True
    return len([c for c in text if c in wb.GREEN | wb.YELLOW | wb.GRAY]) >= 4


def looks_like_keys(text: str) -> bool:
    low = text.lower()
    if re.search(r"нажми|нажмите|press|нажимай|жми|tap\b|keyboard|клавиш", low):
        return True
    if re.search(r"стамин|stamina|вынослив|energy|hp\b|здоров", low):
        return True
    return False


def looks_like_guessing(text: str) -> bool:
    low = text.lower()
    if not re.search(r"угадай|guess|загадал|higher|lower|больше/меньше", low):
        return False
    return bool(re.search(r"\d", text))


def looks_like_grid(text: str) -> bool:
    lines = [l.rstrip() for l in text.splitlines() if l.strip()]
    if len(lines) < 2:
        return False
    lens = {len(re.sub(r"\s", "", l)) for l in lines}
    if len(lens) != 1:
        return False
    n = lens.pop()
    if n < 3:
        return False
    chars = set("".join(re.sub(r"\s", "", l) for l in lines))
    return len(chars & GRID_CHARS) >= max(2, len(chars) // 2)


def parse_stamina(text: str):
    m = re.search(r"(?i)(стамин\w*|stamina|вынослив\w*|energy|hp|здоров\w*)"
                  r"[^\d\-]{0,15}(-?\d+)", text)
    if not m:
        return None
    low = any(w in m.group(1).lower() for w in ("стамин", "stamina", "вынослив"))
    return int(m.group(2)), low


def detect_key(text: str):
    m = re.search(r"(?i)(?:нажми\w*|press|жми|tap)\s*[:\-]?\s*[«\"']?(\w|space|enter)",
                  text)
    if m:
        return m.group(1).lower()
    return None


KEYMAP = {"space": " ", "enter": "\n", "up": "\x1b[A", "down": "\x1b[B",
          "right": "\x1b[C", "left": "\x1b[D", "esc": "\x1b", "tab": "\t"}


def explore_keys(link, screen, spec: str, idle: float = 0.25):
    """Понажимать клавиши и показать, какие меняют экран (для незнакомых игр)."""
    keys = [k.strip() for k in spec.split(",") if k.strip()]
    out = []
    base = screen.text()
    for key in keys:
        payload = KEYMAP.get(key, key)
        before = screen.text()
        if not link.send(payload):
            out.append((key, "закрыто", ""))
            break
        time.sleep(idle)
        data = link.read(quiet=1)
        if not data:
            out.append((key, "нет ответа", ""))
            continue
        screen.feed(data.decode("utf-8", "replace"))
        now = screen.text()
        changed = now != before
        delta = ""
        if changed:
            old = before.splitlines()
            new = now.splitlines()
            for line in new:
                if line not in old:
                    delta = line.strip()[:80]
        out.append((key, "меняет" if changed else "нет", delta))
    return out


def analyze(text: str) -> str:
    view = common.render_screen(text)
    if common.FlagGrabber().feed_text(text):
        return "флаг"
    if looks_like_wordle(view):
        return f"wordle (язык={detect_lang(view)}, длина={detect_length(view) or '?'})"
    if looks_like_keys(view):
        return f"клавиши (key={detect_key(view) or '?'}, стамина={parse_stamina(view)})"
    if looks_like_grid(view):
        return "поле/сетка"
    cls, opts = oracle.classify(view)
    if opts:
        return f"вопрос ({cls}: {', '.join(opts[:3])})"
    return "неизвестно"


def main():
    ap = argparse.ArgumentParser(epilog=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--connect", help="host:port сервиса")
    ap.add_argument("--local", help="локальная команда сервера")
    ap.add_argument("--auto", action="store_true", help="сам определять тип задачи")
    ap.add_argument("--record", help="писать весь протокол в файл")
    ap.add_argument("--plugin", help="python-файл с move(text, state)")
    ap.add_argument("--plugins-dir", default=os.path.join(ROOT, "plugins"),
                    help="папка с плагинами (по умолчанию plugins/)")
    ap.add_argument("--list-plugins", action="store_true",
                    help="показать найденные плагины и выйти")
    ap.add_argument("--words", help="словарь для wordle (по умолчанию по языку)")
    ap.add_argument("--length", type=int, default=0, help="длина слова (0=авто)")
    ap.add_argument("--keys", help="какую клавишу спамить (например q)")
    ap.add_argument("--interval", type=float, default=0.08,
                    help="пауза между нажатиями")
    ap.add_argument("--stamina", type=int, default=25,
                    help="ниже какого значения стамины ждать")
    ap.add_argument("--promote", type=int, default=10)
    ap.add_argument("--attempts", type=int, default=15)
    ap.add_argument("--rounds", type=int, default=500)
    ap.add_argument("--time", type=float, default=0)
    ap.add_argument("--idle", type=float, default=0.15, help="таймаут чтения")
    ap.add_argument("--show-transcript", action="store_true")
    ap.add_argument("--analyze", help="только разобрать текст, без сети")
    ap.add_argument("--no-calibrate", action="store_true",
                    help="не спрашивать про незнакомую разметку (только кэш)")
    ap.add_argument("--explore", action="store_true",
                    help="незнакомый экран: понажимать клавиши и показать реакцию")
    ap.add_argument("--explore-keys",
                    default="w,a,s,d,q,e,space,enter,up,down,left,right,1,2,3,4",
                    help="список клавиш через запятую для --explore")
    args = ap.parse_args()

    if args.analyze:
        print(analyze(args.analyze))
        return 0

    plugins = common.discover_plugins(args.plugins_dir)
    if args.list_plugins:
        if not plugins:
            print(f"[i] в {args.plugins_dir} плагинов нет")
        for path, meta in plugins:
            if meta.get("error"):
                print(f"  [!] {os.path.basename(path)}: {meta['error']}")
                continue
            print(f"  {meta['name']:20} {meta.get('kind', '?'):12} "
                  f"{os.path.basename(path)}")
        return 0

    if bool(args.connect) == bool(args.local):
        ap.error("нужен ровно один из --connect или --local")

    plugin = load_plugin(args.plugin) if args.plugin else None
    started = time.time()
    flag = None
    dump = []
    recorded = open(args.record, "a", encoding="utf-8") if args.record else None

    for attempt in range(1, args.attempts + 1):
        if args.time and time.time() - started > args.time:
            break
        try:
            link = make_link(args)
        except OSError as e:
            print(f"[-] не подключаюсь: {e}")
            break
        state = {"last": "", "round": 0, "history": [], "flags": []}
        mode = None
        wordle = None
        pending_guess = None
        active_plugin = None
        grab = common.FlagGrabber()
        screen = common.Screen()
        last_view = None

        while state["round"] < args.rounds:
            data = link.read()
            if not data:
                break
            text = data.decode("utf-8", "replace")
            if recorded:
                recorded.write(text)
                recorded.write("\n---\n")
            if args.show_transcript:
                print(text.rstrip()[:1500])
            dump.append(text)

            found = grab.feed(data)
            if found:
                flag = found[0]
                print("[!!!] ФЛАГ:", " | ".join(found))
                break
            state["last"] = text
            state["history"].append(text[-400:])
            screen.feed(text)
            view = screen.text()
            state["screen"] = view
            changed = view != last_view
            last_view = view
            if not changed and mode != "keys" and not (
                    active_plugin and active_plugin.get("repeat")):
                continue

            # плагин по баннеру сервиса
            if active_plugin is None and not plugin:
                for _path, meta in plugins:
                    if meta.get("error") or meta.get("kind") != "interactive":
                        continue
                    pat = (meta.get("match") or {}).get("banner")
                    if pat:
                        try:
                            if re.search(pat, text, re.I | re.S):
                                active_plugin = meta
                                print(f"[i] плагин: {meta['name']}")
                                break
                        except re.error:
                            continue

            if active_plugin:
                answer = active_plugin["move"](view, state)
                if answer is not None:
                    nl = "\n" if active_plugin.get("newline", True) else ""
                    link.send(str(answer) + nl)
                    state["round"] += 1
                continue

            # что это вообще
            if mode is None:
                if looks_like_wordle(view):
                    mode = "wordle"
                    lang = "ru" if detect_lang(text) == "ru" else "en"
                    n = args.length or detect_length(text) or 5
                    path = args.words or (r"F:\dev\wordlists\russian5.txt"
                                          if lang == "ru" else
                                          r"F:\dev\wordlists\english5.txt")
                    words = wb.load_words(path, n)
                    if not words:
                        print(f"[-] нет словаря {path} длиной {n}")
                        return 2
                    freq = wb.letter_freq(words)
                    wordle = {"words": words, "freq": freq,
                              "opener": wb.best_opener(words, freq),
                              "cands": list(words), "tried": set(),
                              "pending": None, "used": 0, "n": n,
                              "max": args.promote or 6}
                    print(f"[i] wordle: язык={lang}, длина={n}, "
                          f"слов={len(words)}, первый ход={wordle['opener']}")
                elif looks_like_keys(view):
                    mode = "keys"
                    print(f"[i] клавиши: key={args.keys or detect_key(text)}, "
                          f"стамина={parse_stamina(text)}")
                elif looks_like_guessing(view):
                    mode = "guess"
                    rng = re.search(r"(\d+)\s*(?:до|to|-|\.\.)\s*(\d+)", view)
                    lo, hi = (int(rng.group(1)), int(rng.group(2))) if rng else (1, 100)
                    state["guess"] = {"lo": lo, "hi": hi, "pending": None}
                    print(f"[i] угадайка: диапазон {lo}..{hi} (бинарный поиск)")
                elif looks_like_grid(view):
                    mode = "grid"
                    print("[i] похоже на поле/сетку — сам играть не буду, "
                          "покажу состояние и жду --plugin")
                else:
                    cls, opts = oracle.classify(view)
                    if opts:
                        mode = "qa"
                        print(f"[i] вопрос: {cls} -> {', '.join(opts[:3])}")
                    else:
                        mode = "unknown"

            if args.explore and mode != "unknown":
                print(f"[i] режим {mode}; всё равно разведка клавиш:")
                for key, res, delta in explore_keys(link, screen, args.explore_keys):
                    print(f"  {key:8} {res:10} {delta}")
                break

            if plugin:
                answer = plugin.move(view, state)
                if answer:
                    link.send(answer + "\n")
                    state["round"] += 1
                    continue

            if mode == "wordle" and wordle:
                if wordle["pending"]:
                    parsed = (wb.parse_feedback(text, wordle["n"])
                              or wb.parse_feedback(view, wordle["n"]))
                    if parsed and parsed[0] == "raw":
                        vec = fmt.resolve(parsed[1], view,
                                          interactive=(not args.no_calibrate
                                                       and sys.stdin.isatty()))
                        if vec:
                            parsed = ("vec", vec)
                        else:
                            print("[?] незнакомая разметка:", " ".join(parsed[1]))
                            print("[i] пропиши её: python misc/formats.py --set \"...\" "
                                  "--green ... --yellow ... --gray ...")
                            break
                    if parsed and parsed[0] == "vec":
                        fb = parsed[1]
                        if fb == ["g"] * wordle["n"]:
                            print(f"[+] {wordle['pending']} угадано")
                            wordle.update({"cands": list(wordle["words"]),
                                           "tried": set(), "pending": None,
                                           "used": 0})
                            state["round"] += 1
                            # не ждём баннер следующего раунда: он мог прийти
                            # в этом же чанке — сразу шлём следующее слово
                        else:
                            wordle["cands"] = [w for w in wordle["cands"]
                                               if wb.consistent(w, wordle["pending"], fb)]
                            if not wordle["cands"]:
                                wordle["cands"] = list(wordle["words"])
                            print(f"[i] {wordle['pending']} {''.join(fb)}: "
                                  f"осталось {len(wordle['cands'])}")
                            wordle["pending"] = None
                            wordle["used"] = 0
                    elif parsed and parsed[0] == "count":
                        _, bulls, cows = parsed
                        wordle["cands"] = [w for w in wordle["cands"]
                                           if wb.count_ok(w, wordle["pending"], bulls, cows)]
                        print(f"[i] {wordle['pending']} быки={bulls} коровы={cows}: "
                              f"осталось {len(wordle['cands'])}")
                        wordle["pending"] = None
                        wordle["used"] = 0
                    else:
                        print("[?] не понял разметку ответа. Хвост:")
                        print(text.rstrip()[-400:])
                        print("[i] запиши протокол через --record и сделай плагин")
                        break
                if not wordle["pending"]:
                    if wordle["used"] >= wordle["max"]:
                        print("[-] лимит попыток на слово, сбрасываю")
                        wordle.update({"cands": list(wordle["words"]),
                                       "tried": set(), "used": 0})
                    guess = wb.pick_guess(wordle["cands"], wordle["freq"],
                                          wordle["tried"], wordle["opener"],
                                          wordle["words"])
                    if not guess:
                        break
                    wordle["tried"].add(guess)
                    wordle["pending"] = guess
                    wordle["used"] += 1
                    link.send(guess + "\n")
                    print(f"[>] {guess}")
                continue

            if mode == "guess":
                g = state["guess"]
                resp = text.lower()
                if g["pending"] is not None:
                    mid = g["pending"]
                    if re.search(r"correct|верно|угадал|right|победа|success", resp) and \
                            not re.search(r"не\s*верно|incorrect", resp):
                        g["pending"] = None
                        rng = re.search(r"(\d+)\s*(?:до|to|-|\.\.)\s*(\d+)", view)
                        g["lo"], g["hi"] = ((int(rng.group(1)), int(rng.group(2)))
                                            if rng else (1, 100))
                        state["round"] += 1
                        # не ждём баннер следующего раунда — он мог прийти
                        # в этом же чанке; сразу шлём середину
                    if re.search(r"too high|слишком (больш|много)|перебор|not higher|"
                                 r"не больше|не выше", resp):
                        g["hi"] = mid - 1
                    elif re.search(r"too low|слишком (мал|мало)|не меньше|не ниже", resp):
                        g["lo"] = mid + 1
                    elif re.search(r"higher|больше|выше|more", resp):
                        g["lo"] = mid + 1
                    elif re.search(r"lower|меньше|ниже|less", resp):
                        g["hi"] = mid - 1
                    g["pending"] = None
                if g["lo"] > g["hi"]:
                    g["lo"], g["hi"] = 1, 100
                mid = (g["lo"] + g["hi"]) // 2
                link.send(str(mid) + "\n")
                g["pending"] = mid
                print(f"[>] {mid}  (диапазон {g['lo']}..{g['hi']})")
                state["round"] += 1
                continue

            if mode == "keys":
                st = parse_stamina(view)
                key = args.keys or detect_key(view) or "q"
                if st and st[1] and st[0] < args.stamina:
                    time.sleep(args.interval)
                    continue
                link.send(key)
                time.sleep(args.interval)
                state["round"] += 1
                continue

            if mode == "grid":
                print("[grid]")
                print(view.rstrip()[-1200:])
                print("[i] дальше нужен плагин: какой ход делать — зависит от правил")
                break

            if mode == "qa":
                recent = [l for l in view.splitlines() if l.strip()][-8:]
                digit_lines = [l for l in recent if re.search(r"\d", l)]
                cur = digit_lines[-1] if digit_lines else (
                    recent[-1] if recent else view)
                ppc = ppc_solvers.candidates(cur)
                if ppc:
                    cls = "ppc"
                    opts = [name for name, _ in ppc]
                    answers = dict(ppc)
                else:
                    cls, opts = oracle.classify(cur)
                    answers = {}
                tried = state.setdefault("qa_tried", {}).get(cls, set())
                name = next((o for o in opts if o not in tried), None)
                if name is None:
                    print(f"[?] для {cls} кончились гипотезы")
                    break
                answer = answers[name] if cls == "ppc" else oracle.STRATEGIES[name](cur)
                if answer is None:
                    tried.add(name)
                    state["qa_tried"][cls] = tried
                    continue
                link.send(answer + "\n")
                state["qa_used"] = state.get("qa_used", 0) + 1
                state["round"] += 1
                if state["qa_used"] == args.promote:
                    print(f"[+] {cls}: {name} держится — закрепляю")
                continue

            print("[?] не понял, что происходит. Хвост:")
            print(view.rstrip()[-800:])
            if args.explore:
                print("[i] разведка клавиш:")
                for key, res, delta in explore_keys(link, screen, args.explore_keys):
                    print(f"  {key:8} {res:10} {delta}")
                print("[i] что реагирует — то и закладывай в плагин")
            else:
                print("[i] --record game.log, потом плагин move(text, state); "
                      "или --explore, чтобы найти рабочие клавиши")
            break

        link.close()
        if flag:
            break
        if mode == "unknown":
            break
        # на обрыве — следующая попытка (другая стратегия подберётся сама)
        time.sleep(0.2)

    if recorded:
        recorded.close()
        print(f"[i] протокол: {args.record}")
    if not flag and dump:
        print("[i] флаг не найден; последние ответы сохранены в --record")
    return 0 if flag else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (FileNotFoundError, IsADirectoryError, PermissionError) as e:
        print(f"[-] не могу открыть: {getattr(e, 'filename', None) or e}")
    except BrokenPipeError:
        pass
    except KeyboardInterrupt:
        print("\n[-] прервано")
