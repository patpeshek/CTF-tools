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

    def __init__(self, root: str):
        self.root = os.path.abspath(root)

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

    def run(self, cmd: str, timeout: int = DEFAULT_CMD_TIMEOUT) -> str:
        ok, why = guard.check_command(cmd)
        if not ok:
            return f"ОТКАЗ: {why}"
        try:
            proc = subprocess.run(cmd, cwd=self.root, shell=True,
                                  capture_output=True, text=True,
                                  encoding="utf-8", errors="replace",
                                  timeout=timeout)
        except subprocess.TimeoutExpired:
            return f"TIMEOUT {timeout}s"
        except OSError as exc:
            return f"OSERROR: {exc}"
        out = ((proc.stdout or "") + (proc.stderr or "")).strip()
        if len(out) > MAX_OUT:
            out = out[:MAX_OUT] + "\n...[обрезано]"
        return f"rc={proc.returncode}\n{out}"

    def run_py(self, code: str, timeout: int = DEFAULT_CMD_TIMEOUT) -> str:
        fd, path = tempfile.mkstemp(suffix=".py", dir=self.root)
        os.close(fd)
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(code)
        try:
            return self.run(f'"{sys.executable}" -I "{os.path.basename(path)}"',
                            timeout=timeout)
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
        try:
            proc = subprocess.run(argv, cwd=self.root, capture_output=True,
                                  text=True, encoding="utf-8",
                                  errors="replace", timeout=timeout)
        except subprocess.TimeoutExpired:
            return f"TIMEOUT {timeout}s"
        except OSError as exc:
            return f"OSERROR: {exc}"
        out = ((proc.stdout or "") + (proc.stderr or "")).strip()
        if len(out) > MAX_OUT:
            out = out[:MAX_OUT] + "\n...[обрезано]"
        return f"rc={proc.returncode}\n{out}"


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
  * Если флага нет — НЕ выдумывай его. Верни answer/not_found с короткой
    причиной (что проверил и чего не хватило).
  * Флаг возвращай только когда он реально был в выводе команды.

Экономия шагов: сначала list, потом один-два точных шага, а не перебор всего.

Необязательное поле "thought" — короткая заметка, зачем делаешь шаг
(например {"thought":"проверю заголовок","action":"bash","cmd":"xxd -l 64 f"}).
"""


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
    # запасной путь: вытащить первый объект, если провайдер добавил текст
    if text.startswith("```"):
        text = re.sub(r"^```[a-zA-Z]*\s*|\s*```$", "", text).strip()
    m = JSON_RE.search(text)
    if not m:
        return None
    try:
        obj = json.loads(m.group(0))
    except json.JSONDecodeError:
        return None
    return obj if isinstance(obj, dict) and "action" in obj else None


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
                             "Это не флаг. Продолжай."})
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
                   "detail": " ".join(str(a) for a in args)[:100]}
            result = ws.toolbox(name, args)
            yield {"event": "agent_step", "n": step,
                   "tool": f"tool:{name}",
                   "detail": f"{time.time() - started:.1f}s"}
        elif kind == "bash":
            started = time.time()
            cmd = str(action.get("cmd", ""))
            allowed, why = guard.check_command(cmd)
            yield {"event": "agent_step", "n": step, "tool": "bash",
                   "detail": (cmd if allowed else f"отказ: {why}")[:120]}
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
