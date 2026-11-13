#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
deepseek.py — клиент DeepSeek и разбор задачи моделью.

Ключ берётся ТОЛЬКО из окружения `DEEPSEEK_API_KEY` — в коде, логах и git его
нет (см. .gitignore). Задаётся пользователем:

    setx DEEPSEEK_API_KEY "sk-..."      # Windows, разово в системе
    $env:DEEPSEEK_API_KEY="sk-..."      # PowerShell, на сессию
    export DEEPSEEK_API_KEY="sk-..."    # bash

API совместим с OpenAI (base https://api.deepseek.com, /chat/completions).
Только стандартная библиотека.

    python site/ai/deepseek.py ping
    python site/ai/deepseek.py analyze chal.py
"""
from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

API_BASE = os.environ.get("DEEPSEEK_API_BASE", "https://api.deepseek.com")
MODEL = os.environ.get("DEEPSEEK_MODEL", "deepseek-chat")
MAX_INPUT = 24000  # символов задачи в промпт, чтобы не раздувать запрос


class NoKey(RuntimeError):
    pass


class APIError(RuntimeError):
    pass


def _key() -> str:
    k = (os.environ.get("DEEPSEEK_API_KEY") or "").strip()
    if not k:
        raise NoKey("нет DEEPSEEK_API_KEY в окружении — задай ключ переменной окружения")
    return k


def chat(messages, *, model=None, temperature=0.2, max_tokens=1500, timeout=180) -> str:
    """Один вызов chat-completions. Возвращает текст ответа."""
    body = json.dumps({
        "model": model or MODEL,
        "messages": messages,
        "temperature": temperature,
        "max_tokens": max_tokens,
        "stream": False,
    }).encode("utf-8")
    req = urllib.request.Request(
        API_BASE.rstrip("/") + "/chat/completions",
        data=body, method="POST",
        headers={"Authorization": "Bearer " + _key(),
                 "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.loads(r.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", "replace")[:400]
        raise APIError(f"HTTP {e.code}: {detail}")
    except urllib.error.URLError as e:
        raise APIError(f"сеть: {e.reason}")
    try:
        return data["choices"][0]["message"]["content"]
    except (KeyError, IndexError):
        raise APIError(f"неожиданный ответ: {json.dumps(data)[:300]}")


SYSTEM = (
    "Ты эксперт по CTF и прикладной безопасности. Тебе дают артефакт или ИСХОДНИК "
    "задачи. Определи категорию (crypto/pwn/rev/web/stego/forensic/misc/ppc) и тип, "
    "найди уязвимость или трюк и дай КОНКРЕТНЫЙ план решения: какие шаги, какие "
    "инструменты, какой код написать. Если это исходник сервиса — укажи, что надо "
    "подключиться к host:port, и опиши протокол атаки. Не выдумывай флаг, которого "
    "не видишь. Отвечай кратко и по делу, по-русски."
)


def analyze(challenge_text: str, *, solve_summary: str = "", filename: str = "",
            model=None) -> str:
    """Разобрать задачу моделью: категория, уязвимость, план решения."""
    text = challenge_text[:MAX_INPUT]
    parts = []
    if filename:
        parts.append(f"Имя файла: {filename}")
    if solve_summary:
        parts.append("Что уже попробовал локальный кит (solve):\n" + solve_summary[:3000])
    parts.append("Содержимое задачи:\n```\n" + text + "\n```")
    return chat([
        {"role": "system", "content": SYSTEM},
        {"role": "user", "content": "\n\n".join(parts)},
    ], model=model)


def _read_target(path: str) -> tuple[str, str]:
    data = open(path, "rb").read(MAX_INPUT * 2)
    try:
        return data.decode("utf-8"), os.path.basename(path)
    except UnicodeDecodeError:
        return data.decode("latin-1", "replace"), os.path.basename(path)


def main(argv):
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__)
        return 0
    cmd = argv[0]
    try:
        if cmd == "ping":
            print(chat([{"role": "user", "content": "Ответь одним словом: pong"}],
                       max_tokens=10))
            return 0
        if cmd == "analyze":
            if len(argv) < 2:
                print("нужен путь к файлу: analyze <файл>")
                return 2
            text, name = _read_target(argv[1])
            print(analyze(text, filename=name))
            return 0
        print(f"неизвестная команда: {cmd}")
        return 2
    except NoKey as e:
        print(f"[-] {e}")
        return 3
    except APIError as e:
        print(f"[-] ошибка API: {e}")
        return 4


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
