#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""client.py — минимальный клиент OpenAI-совместимого chat-completions.

Настройки (в порядке приоритета):
  1. переменные окружения: SOLVER_API_URL, SOLVER_API_KEY, SOLVER_MODEL;
  2. файл site/engine/.env  (KEY=VALUE, по строке; в git не попадает).

Ничего не логирует: ключ не печатается и не сохраняется.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ENV_FILE = os.path.join(HERE, ".env")


def _load_env_file() -> dict:
    out = {}
    try:
        with open(ENV_FILE, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                out[k.strip()] = v.strip().strip('"').strip("'")
    except OSError:
        pass
    return out


def settings() -> dict:
    file_env = _load_env_file()

    def pick(name: str, default: str = "") -> str:
        return os.environ.get(name) or file_env.get(name) or default

    base = pick("SOLVER_API_URL") or pick("OPENAI_BASE_URL")
    key = pick("SOLVER_API_KEY") or pick("OPENAI_API_KEY")
    model = pick("SOLVER_MODEL")
    if base and not base.rstrip("/").endswith("/v1"):
        base = base.rstrip("/") + "/v1"
    return {"base": base, "key": key, "model": model}


def ready() -> bool:
    return all(settings().values())


def chat(messages, *, model: str | None = None, temperature: float = 0.2,
         max_tokens: int = 2000, timeout: int = 120,
         json_mode: bool = False) -> str:
    cfg = settings()
    if not cfg["key"] or not cfg["base"]:
        raise RuntimeError("нет SOLVER_API_URL / SOLVER_API_KEY "
                           "(переменные окружения или site/engine/.env)")
    payload = {
        "model": model or cfg["model"],
        "messages": messages,
        "temperature": temperature,
        "max_tokens": max_tokens,
    }
    if json_mode:
        payload["response_format"] = {"type": "json_object"}
    try:
        return _post(cfg, payload, timeout)
    except RuntimeError as exc:
        # провайдер может не знать response_format — повторяем без него
        if json_mode and "response_format" in str(exc):
            payload.pop("response_format", None)
            return _post(cfg, payload, timeout)
        raise


def _post(cfg: dict, payload: dict, timeout: int) -> str:
    req = urllib.request.Request(
        cfg["base"].rstrip("/") + "/chat/completions",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json",
                 "Authorization": "Bearer " + cfg["key"]},
        method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", "replace")[:300]
        raise RuntimeError(f"HTTP {exc.code}: {body}") from exc
    try:
        return data["choices"][0]["message"]["content"] or ""
    except (KeyError, IndexError) as exc:
        raise RuntimeError(f"неожиданный ответ: {str(data)[:300]}") from exc
