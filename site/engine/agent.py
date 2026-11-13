#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""agent.py — цикл решения задачи с инструментами.

Инструменты (реальные):
  * write / read / list — файлы в рабочей папке задачи;
  * bash — команда оболочки (стоп-лист в guard.py);
  * py — запуск python-кода;
  * flag / answer — итог.

Протокол ответа — один JSON-объект на шаг, необязательное поле `thought`
для рассуждений (в интерфейс не попадает, если не включён режим рассуждений):
  {"thought":"...","action":"bash","cmd":"..."}
  {"thought":"...","action":"py","code":"..."}
  {"action":"write","path":"...","content":"..."}
  {"action":"read","path":"..."}
  {"action":"list"}
  {"action":"flag","flag":"..."}
  {"action":"answer","status":"not_found","text":"..."}
  {"action":"answer","status":"need_service","text":"host:port"}
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
import time

import client
import guard

FLAG_RE = re.compile(r"[A-Za-z][A-Za-z0-9_]{1,15}\{[^{}\r\n]{1,200}\}")
JSON_RE = re.compile(r"\{.*\}", re.S)


def looks_like_flag(text: str) -> bool:
    """Настоящий флаг, а не пример из справки вида CTF{...}."""
    m = FLAG_RE.search(text or "")
    if not m:
        return False
    inner = m.group(0).split("{", 1)[1][:-1]
    core = re.sub(r"[^A-Za-z0-9]", "", inner)
    if len(core) < 4:
        return False
    if set(inner) <= set(".… "):
        return False
    return True

MAX_OUT = 6000
DEFAULT_CMD_TIMEOUT = 45
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
TOOLBOX = os.path.join(ROOT, "toolbox.py")


def _tool_name_ok(name: str) -> bool:
    return bool(re.fullmatch(r"[a-z][a-z0-9_]{0,30}", name or ""))


class Workspace:
    """Рабочая папка задачи: всё внутри корня, ничего наружу."""

    def __init__(self, root: str, cancel=None):
        self.root = os.path.abspath(root)
        self.cancel = cancel

    def safe(self, rel: str) -> str:
        rel = (rel or "").replace("\\", "/").lstrip("/")
        path = os.path.abspath(os.path.join(self.root, rel))
        if os.path.commonpath([path, self.root]) != self.root:
            raise ValueError("путь вне рабочей папки")
        return path

    def write(self, rel: str, content: str) -> str:
        path = self.safe(rel)
        os.makedirs(os.path.dirname(path) or self.root, exist_ok=True)
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(content)
        return f"{rel}: записано {len(content)} символов"

    def read(self, rel: str, limit: int = 20000) -> str:
        path = self.safe(rel)
        with open(path, "rb") as fh:
            data = fh.read(limit + 1)
        text = data[:limit].decode("utf-8", "replace")
        return text + ("\n...[обрезано]" if len(data) > limit else "")

    def tree(self) -> str:
        rows = []
        for base, _dirs, files in os.walk(self.root):
            for name in sorted(files):
                path = os.path.join(base, name)
                rel = os.path.relpath(path, self.root).replace("\\", "/")
                rows.append(f"{os.path.getsize(path):>10}  {rel}")
        return "\n".join(rows) or "(пусто)"

    def _exec(self, argv, timeout: int, shell: bool = False) -> str:
        try:
            proc = subprocess.Popen(argv, cwd=self.root, shell=shell,
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, text=True,
                                    encoding="utf-8", errors="replace")
        except OSError as exc:
            return f"OSERROR: {exc}"
        end = time.time() + timeout
        while True:
            if self.cancel and self.cancel():
                proc.kill()
                proc.communicate()
                return "ОСТАНОВЛЕНО пользователем"
            try:
                out, err = proc.communicate(timeout=0.4)
                break
            except subprocess.TimeoutExpired:
                if time.time() > end:
                    proc.kill()
                    proc.communicate()
                    return f"TIMEOUT {timeout}s"
        text = ((out or "") + (err or "")).strip()
        if len(text) > MAX_OUT:
            text = text[:MAX_OUT] + "\n...[обрезано]"
        return f"rc={proc.returncode}\n{text}"

    def run(self, cmd: str, timeout: int = DEFAULT_CMD_TIMEOUT) -> str:
        ok, why = guard.check_command(cmd)
        if not ok:
            return f"ОТКАЗ: {why}"
        return self._exec(cmd, timeout, shell=True)

    def run_py(self, code: str, timeout: int = DEFAULT_CMD_TIMEOUT) -> str:
        fd, path = tempfile.mkstemp(suffix=".py", dir=self.root)
        os.close(fd)
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(code)
        try:
            return self._exec([sys.executable, "-I", os.path.basename(path)],
                              timeout)
        finally:
            try:
                os.remove(path)
            except OSError:
                pass

    def toolbox(self, name: str, args: list[str],
                timeout: int = 120) -> str:
        """Вызов инструмента проекта: python toolbox.py <name> <args...>."""
        if not _tool_name_ok(name):
            return f"ОТКАЗ: недопустимое имя инструмента {name!r}"
        if not os.path.isfile(TOOLBOX):
            return f"ОТКАЗ: не найден {TOOLBOX}"
        argv = [sys.executable, TOOLBOX, name] + [str(a) for a in args][:20]
        return self._exec(argv, timeout)


SYSTEM = """Ты автономный решатель CTF-задач.

Рабочая папка: файлы задачи уже лежат в ней. Доступные действия:
  {"action":"list"}
  {"action":"read","path":"файл"}
  {"action":"write","path":"sol.py","content":"..."}
  {"action":"tool","name":"rsa","args":["auto","keys.txt"]}
  {"action":"tool","name":"index"}
  {"action":"bash","cmd":"команда"}
  {"action":"py","code":"python-код"}
  {"action":"flag","flag":"НАЙДЕННЫЙ_ФЛАГ"}
  {"action":"answer","status":"not_found","text":"почему не вышло"}
  {"action":"answer","status":"need_service","text":"host:port"}

В проекте есть готовые инструменты (тот же toolbox.py). Сначала смотри список
через {"action":"tool","name":"index"} — там всё: rsa, enc, xor, hash, triage,
carve, chain, ws, audio, pcap, dns, jwt, lsb, zip, sqlite, elf и другие.
Если задача про RSA/кодировки/архивы/картинки/трафик — СНАЧАЛА вызывай готовый
инструмент, а свой скрипт пиши только если готового нет или он не справился.
Пример: {"action":"tool","name":"rsa","args":["auto","chall.txt"]}.

Типовые заходы (не изобретай своё, если есть готовое):
  * файл незнакомого типа → {"action":"tool","name":"triage","args":["файл"]};
  * RTF/DOCX/PDF/ZIP с текстом → {"action":"tool","name":"text","args":["файл"]};
  * подозрение на пробелы/невидимые символы → {"action":"tool","name":"ws",
    "args":["файл"]} (режим auto сам перебирает схемы: таб/пробел, 5-8 бит,
    сдвиги, реверс, длины серий);
  * шифротекст + текстовый словарь → {"action":"tool","name":"classical",
    "args":["vigdict","--text","ШИФР","--words","words.txt"]};
    если словарь рядом есть — это ОБЯЗАТЕЛЬНЫЙ первый шаг, свой скрипт для
    Виженера не пиши (перебор алфавитов и рейтинг уже внутри инструмента);
  * классический шифр без ключа → {"action":"tool","name":"classical",
    "args":["vigenere-crack","--text","ШИФР"]} или autocrack.

Правила (обязательны):
  * Отвечай РОВНО одним JSON-объектом. Никакого текста вокруг, никакого
    markdown, никаких ```блоков``` — только JSON.
  * Работай только внутри рабочей папки. Никаких путей вида C:\\, /, ..
  * ЗАПРЕЩЕНО: удалять и форматировать диски, менять реестр, выключать машину,
    убивать процессы, ставить/сносить пакеты системы, скачивать и запускать
    скрипты из интернета, трогать чужие файлы и домашнюю папку.
  * Никакой отправки файлов и данных наружу.
  * Для задач, которым нужен интернет, используй только разрешённые адреса
    из условия; если сети нет — верни need_service.
  * Не используй echo в терминале — ни для вывода текста, ни для записи файлов,
    тем более с русским текстом. Для файлов есть write, для проверок — py.
    Терминал нужен только для запуска программ и утилит.
  * Если флага нет — НЕ выдумывай его. Верни answer/not_found с короткой
    причиной (что проверил и чего не хватило).
  * Флаг возвращай только когда он реально был в выводе команды.

Экономия шагов: сначала list, потом один-два точных шага, а не перебор всего.

Необязательное поле "thought" — короткая заметка, зачем делаешь шаг
(например {"thought":"проверю заголовок","action":"bash","cmd":"xxd -l 64 f"}).
"""


def _balanced_json(text: str):
    """Все фрагменты text, начинающиеся с '{' и сбалансированные по скобкам."""
    for start, ch in enumerate(text):
        if ch != "{":
            continue
        depth, in_str, esc = 0, False, False
        for i in range(start, len(text)):
            c = text[i]
            if in_str:
                if esc:
                    esc = False
                elif c == "\\":
                    esc = True
                elif c == '"':
                    in_str = False
                continue
            if c == '"':
                in_str = True
            elif c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    yield text[start:i + 1]
                    break


def _parse_action(text: str) -> dict | None:
    text = (text or "").strip()
    if not text:
        return None
    # строгий режим: ответ целиком должен быть JSON
    try:
        obj = json.loads(text)
        if isinstance(obj, dict) and "action" in obj:
            return obj
    except json.JSONDecodeError:
        pass
    if text.startswith("```"):
        text = re.sub(r"^```[a-zA-Z]*\s*|\s*```$", "", text).strip()
    # фрагменты: первый сбалансированный объект, затем «починка» мелочей
    for chunk in _balanced_json(text):
        for variant in (chunk,
                        re.sub(r",\s*([}\]])", r"\1", chunk),
                        re.sub(r"'([^']*)'", r'"\1"', chunk)):
            try:
                obj = json.loads(variant)
            except json.JSONDecodeError:
                continue
            if isinstance(obj, dict) and "action" in obj:
                return obj
    m = JSON_RE.search(text)
    if not m:
        return None
    try:
        obj = json.loads(m.group(0))
    except json.JSONDecodeError:
        return None
    return obj if isinstance(obj, dict) and "action" in obj else None


def _file_hints(root: str) -> str:
    """Детерминированные подсказки по файлам: словарь, шифротекст, RTF, архив."""
    files = []
    try:
        for n in sorted(os.listdir(root))[:60]:
            p = os.path.join(root, n)
            if os.path.isfile(p) and os.path.getsize(p) <= 2_000_000:
                files.append((n, p, os.path.getsize(p)))
    except OSError:
        return ""
    if not files:
        return ""
    hints = []
    wordlist = next((n for n, _, _ in files
                     if re.search(r"(word|pass|cand|dict)", n, re.I)
                     and n.lower().endswith((".txt", ".lst"))), None)
    if wordlist:
        hints.append(f"есть словарь {wordlist} — ключи/пароли ищутся по нему")
        for n, p, size in files:
            if n == wordlist or size > 600:
                continue
            try:
                txt = open(p, encoding="utf-8", errors="replace").read().strip()
            except OSError:
                continue
            first = txt.splitlines()[0].strip() if txt else ""
            if (8 <= len(first) <= 400 and " " not in first
                    and re.search(r"[A-Za-z]", first)
                    and re.search(r"[0-9_]", first)):
                hints.append(
                    'похоже на шифротекст ' + n + ': '
                    '{"action":"tool","name":"classical","args":["vigdict",'
                    '"--text","' + first + '","--words","' + wordlist + '"]}')
                break
    for n, p, size in files:
        try:
            head = open(p, "rb").read(8)
        except OSError:
            continue
        if head.startswith(b"{\\rtf"):
            hints.append(
                n + " — это RTF: сначала "
                '{"action":"tool","name":"text","args":["' + n + '"]}, '
                'потом {"action":"tool","name":"ws","args":["' + n + '"]}')
        elif head.startswith(b"PK\x03\x04"):
            hints.append(n + " — архив: " +
                         '{"action":"tool","name":"triage","args":["' + n + '"]}')
    if not hints:
        return ""
    return "\n\nЧто видно по файлам (проверено заранее):\n- " + "\n- ".join(hints)


def run(ws: Workspace, task_text: str, *, max_steps: int = 14,
        deadline: float | None = None, cmd_timeout: int = DEFAULT_CMD_TIMEOUT,
        model: str | None = None, reasoning: bool = False,
        show_thoughts: bool = False, cancel=None):
    """Генератор событий. Останавливается на флаге/ответе/лимитах."""
    deadline = deadline or (time.time() + 600)
    listing = ws.tree()
    messages = [
        {"role": "system", "content": SYSTEM},
        {"role": "user", "content":
            f"Условие задачи:\n{task_text or '(не задано)'}\n\n"
            f"Файлы в рабочей папке:\n{listing}"},
    ]
    if reasoning:
        messages.append({"role": "user", "content":
                         "Перед каждым действием заполняй поле thought "
                         "короткой заметкой о плане."})

    for step in range(1, max_steps + 1):
        if cancel and cancel():
            yield {"event": "agent_stop", "reason": "остановлено"}
            return
        if time.time() > deadline:
            yield {"event": "agent_stop", "reason": "время вышло"}
            return
        try:
            reply = client.chat(messages, model=model, temperature=0.15,
                                max_tokens=1800, json_mode=True)
        except Exception as exc:
            yield {"event": "agent_stop", "reason": f"модель недоступна: {exc}"}
            return
        action = _parse_action(reply)
        if not action:
            messages.append({"role": "assistant", "content": reply})
            messages.append({"role": "user", "content":
                             'Ответ должен быть ровно одним JSON-объектом '
                             'вида {"action":"..."}.'})
            yield {"event": "agent_step", "n": step, "tool": "формат",
                   "detail": "ответ не распознан"}
            continue

        thought = str(action.get("thought", "")).strip()
        if thought and show_thoughts:
            yield {"event": "thought", "text": thought[:500]}

        kind = str(action.get("action", "")).lower()
        messages.append({"role": "assistant", "content": reply})

        if kind == "flag":
            raw = str(action.get("flag", "")).strip()
            if looks_like_flag(raw):
                yield {"event": "flag", "flag": FLAG_RE.search(raw).group(0),
                       "source": "agent"}
                return
            yield {"event": "agent_step", "n": step, "tool": "flag",
                   "detail": "не похоже на флаг"}
            messages.append({"role": "user", "content":
                             "Это не флаг: флаг — одна строка вида prefix{...} "
                             "без пробелов и кавычек. Если расшифровка дала "
                             "текст с {...} внутри — верни ровно его. Если флага "
                             "в выводе не было, продолжай решать."})
            continue

        if kind == "answer":
            status = str(action.get("status", "done") or "done").lower()
            text = str(action.get("text", ""))[:800]
            yield {"event": "answer", "status": status, "text": text}
            return

        result = ""
        if kind == "list":
            result = ws.tree()
            yield {"event": "agent_step", "n": step, "tool": "list",
                   "detail": f"{len(result.splitlines())} файлов"}
        elif kind == "read":
            try:
                result = ws.read(str(action.get("path", "")))
            except (OSError, ValueError) as exc:
                result = f"ошибка чтения: {exc}"
            yield {"event": "agent_step", "n": step, "tool": "read",
                   "detail": str(action.get("path", ""))}
        elif kind == "write":
            try:
                result = ws.write(str(action.get("path", "x.py")),
                                  str(action.get("content", "")))
            except (OSError, ValueError) as exc:
                result = f"ошибка записи: {exc}"
            yield {"event": "agent_step", "n": step, "tool": "write",
                   "detail": str(action.get("path", ""))}
        elif kind == "py":
            started = time.time()
            result = ws.run_py(str(action.get("code", "")), timeout=cmd_timeout)
            yield {"event": "agent_step", "n": step, "tool": "py",
                   "detail": f"{time.time() - started:.1f}s"}
        elif kind == "tool":
            name = str(action.get("name", ""))
            args = action.get("args")
            if isinstance(args, str):
                args = [args]
            if not isinstance(args, list):
                args = []
            started = time.time()
            yield {"event": "agent_step", "n": step,
                   "tool": f"tool:{name}",
                   "detail": f"аргументов: {len(args)}"}
            result = ws.toolbox(name, args)
            yield {"event": "agent_step", "n": step,
                   "tool": f"tool:{name}",
                   "detail": f"{time.time() - started:.1f}s"}
        elif kind == "bash":
            started = time.time()
            cmd = str(action.get("cmd", ""))
            allowed, why = guard.check_command(cmd)
            yield {"event": "agent_step", "n": step, "tool": "bash",
                   "detail": "выполняю…" if allowed else f"отказ: {why}"[:80]}
            result = ws.run(cmd, timeout=cmd_timeout) if allowed else f"ОТКАЗ: {why}"
            if allowed:
                yield {"event": "agent_step", "n": step, "tool": "bash",
                       "detail": f"{time.time() - started:.1f}s"}
        else:
            result = f"неизвестное действие: {kind}"
            yield {"event": "agent_step", "n": step, "tool": kind,
                   "detail": "неизвестное действие"}

        found = None if kind == "tool" and "index" in str(action.get("name")) \
            else FLAG_RE.search(result)
        if found and looks_like_flag(found.group(0)):
            yield {"event": "flag", "flag": found.group(0), "source": "agent"}
            return

        yield {"event": "agent_output", "text": result[:1200]}
        messages.append({"role": "user", "content":
                         f"Результат шага {step}:\n```\n{result[:4000]}\n```\n"
                         "Что дальше? Один JSON-объект."})

    yield {"event": "answer", "status": "not_found",
           "text": f"лимит шагов ({max_steps})"}
