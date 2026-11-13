#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""agent.py — цикл решения задачи с инструментами.

Что умеет агент (реально, без имитации):
  * писать/читать файлы в рабочей папке задачи;
  * запускать команды оболочки (терминал) с таймаутом;
  * запускать python-код;
  * смотреть список файлов;
  * объявлять флаг или ответ «нужен сервис».

Протокол ответа модели — один JSON-объект на шаг:
  {"action":"bash","cmd":"..."}
  {"action":"py","code":"..."}
  {"action":"write","path":"...","content":"..."}
  {"action":"read","path":"..."}
  {"action":"list"}
  {"action":"flag","flag":"..."}
  {"action":"answer","text":"..."}

Каждый шаг отдаётся наружу событиями (что именно запущено и что вернулось),
поэтому в интерфейсе видно реальную работу, а не «магию».
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

FLAG_RE = re.compile(r"[A-Za-z][A-Za-z0-9_]{1,15}\{[^{}\r\n]{1,200}\}")
JSON_RE = re.compile(r"\{.*\}", re.S)

MAX_OUT = 6000
DEFAULT_CMD_TIMEOUT = 45


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


SYSTEM = """Ты автономный решатель задач по информационной безопасности.

У тебя есть рабочая папка, в ней лежат файлы задачи. Ты можешь:
  * писать файлы, чтобы собрать скрипт;
  * запускать команды оболочки и python;
  * читать файлы и смотреть список.

Отвечай РОВНО одним JSON-объектом, без пояснений и без markdown:
  {"action":"bash","cmd":"команда"}
  {"action":"py","code":"python-код"}
  {"action":"write","path":"имя_файла.py","content":"..."}
  {"action":"read","path":"имя_файла"}
  {"action":"list"}
  {"action":"flag","flag":"НАЙДЕННЫЙ_ФЛАГ"}
  {"action":"answer","text":"если без внешнего сервиса/тулзы никак"}

Правила:
  * Сначала осмотрись: {"action":"list"}, затем читай/запускай.
  * Каждый шаг делай маленьким и проверяемым: написал скрипт — запусти его.
  * Если данных мало, но решать можно — решай; не спрашивай разрешения.
  * Флаг возвращай только когда реально получил его на выводе.
  * Никаких выдуманных флагов. Не уверен — продолжай исследовать.
"""


def _parse_action(text: str) -> dict | None:
    text = (text or "").strip()
    if not text:
        return None
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
        model: str | None = None):
    """Генератор событий. Останавливается на флаге/ответе/лимитах."""
    deadline = deadline or (time.time() + 600)
    listing = ws.tree()
    messages = [
        {"role": "system", "content": SYSTEM},
        {"role": "user", "content":
            f"Условие задачи:\n{task_text or '(не задано)'}\n\n"
            f"Файлы в рабочей папке:\n{listing}"},
    ]

    for step in range(1, max_steps + 1):
        if time.time() > deadline:
            yield {"event": "agent_stop", "reason": "время вышло"}
            return
        try:
            reply = client.chat(messages, model=model, temperature=0.1,
                                max_tokens=1800)
        except Exception as exc:  # сеть/ключ/лимиты
            yield {"event": "agent_stop", "reason": f"модель недоступна: {exc}"}
            return
        action = _parse_action(reply)
        if not action:
            messages.append({"role": "assistant", "content": reply})
            messages.append({"role": "user", "content":
                             "Ответ должен быть ровно одним JSON-объектом "
                             'вида {"action":"..."}.'})
            yield {"event": "agent_step", "n": step, "tool": "формат",
                   "detail": "ответ не распознан"}
            continue

        kind = str(action.get("action", "")).lower()
        messages.append({"role": "assistant", "content": reply})

        if kind == "flag":
            flag = str(action.get("flag", "")).strip()
            if FLAG_RE.fullmatch(flag) or FLAG_RE.search(flag):
                found = FLAG_RE.search(flag).group(0)
                yield {"event": "flag", "flag": found, "source": "agent"}
                return
            yield {"event": "agent_step", "n": step, "tool": "flag",
                   "detail": "не похоже на флаг"}
            messages.append({"role": "user", "content":
                             "Это не флаг. Продолжай."})
            continue

        if kind == "answer":
            yield {"event": "answer", "text": str(action.get("text", ""))[:800]}
            return

        if kind == "list":
            result = ws.tree()
            yield {"event": "agent_step", "n": step, "tool": "list",
                   "detail": f"{len(result.splitlines())} файлов"}
        elif kind == "read":
            try:
                result = ws.read(str(action.get("path", "")))
            except OSError as exc:
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
        elif kind == "bash":
            started = time.time()
            cmd = str(action.get("cmd", ""))
            yield {"event": "agent_step", "n": step, "tool": "bash",
                   "detail": cmd[:120]}
            result = ws.run(cmd, timeout=cmd_timeout)
            yield {"event": "agent_step", "n": step, "tool": "bash",
                   "detail": f"{time.time() - started:.1f}s"}
        else:
            result = f"неизвестное действие: {kind}"
            yield {"event": "agent_step", "n": step, "tool": kind,
                   "detail": "неизвестное действие"}

        found = FLAG_RE.search(result)
        if found:
            yield {"event": "flag", "flag": found.group(0), "source": "agent"}
            return

        yield {"event": "agent_output", "text": result[:1200]}
        messages.append({"role": "user", "content":
                         f"Результат шага {step}:\n```\n{result[:4000]}\n```\n"
                         "Что дальше? Один JSON-объект."})

    yield {"event": "agent_stop", "reason": f"лимит шагов ({max_steps})"}
