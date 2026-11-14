#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""guard.py — защита от разрушительных команд.

Работает как «стоп-лист»: сомнительные команды не выполняются, а агенту
возвращается текст с причиной. Это не полноценная песочница (для неё — Docker),
но она закрывает типовые способы убить систему по ошибке решателя.

Отключить можно только осознанно: AGENT_ALLOW_DANGEROUS=1.
"""
from __future__ import annotations

import os
import re

# (регулярка, причина)
DENY = [
    (r"\brm\s+(-[a-zA-Z]*\s+)*-?[a-zA-Z]*[rf][a-zA-Z]*\s+(/|~|\$HOME|\*)\s*$",
     "удаление корня/дома"),
    (r"\brm\s+-rf\s+/(\s|$)", "удаление корня"),
    (r"\bdd\b[^\n]*of\s*=\s*/dev/(sd|nvme|hd|disk)", "запись на диск"),
    (r"\bmkfs(\.\w+)?\b", "форматирование"),
    (r"\bformat\s+[a-zA-Z]:", "форматирование диска"),
    (r"\bdiskpart\b", "управление разделами"),
    (r"\bbcdedit\b", "загрузчик"),
    (r"(?:^|[;&|]\s*|\bsudo\s+)(shutdown|reboot|halt|poweroff)\b", "выключение машины"),
    (r"\bStop-Computer\b|\bRestart-Computer\b", "выключение машины"),
    (r"\btaskkill\b[^\n]*/f", "массовое убийство процессов"),
    (r"\bkill(all)?\s+-9\s+(-1|1)\b", "убийство всех процессов"),
    (r"\bdel\s+/[sfq]\b[^\n]*[a-zA-Z]:\\", "удаление с диска"),
    (r"Remove-Item[^\n]*-Recurse[^\n]*([a-zA-Z]:\\|/)\s*$", "рекурсивное удаление"),
    (r"\breg\s+delete\b", "правка реестра"),
    (r"\bnet\s+user\b[^\n]*/add", "создание пользователя"),
    (r"\b(chmod|chown)\s+-R\s+[0-7]*\s+/(\s|$)", "права на корень"),
    (r"\bcipher\s+/w\b|\bsfc\s+/scannow\b|\bchkdsk\b", "служебные операции с диском"),
    (r"(curl|wget)[^\n|]*\|\s*(ba)?sh", "скачать и выполнить скрипт"),
    (r"powershell[^\n]*-enc(odedcommand)?\b", "скрытый powershell"),
    (r":\(\)\s*\{\s*:\|:&\s*\};:", "fork-бомба"),
    (r"(?:^|[;&|]\s*|\bsudo\s+)(mount|umount)\b", "монтирование"),
    (r"\b(apt|yum|dnf|pacman)\s+(remove|purge)\b", "удаление пакетов"),
    (r"\bpip\s+uninstall\b[^\n]*\b(pillow|numpy|crypto|scapy)\b",
     "снос зависимостей проекта"),
]
_DENY = [(re.compile(p, re.I), why) for p, why in DENY]

MAX_CMD = 2000


def allow_all() -> bool:
    return os.environ.get("AGENT_ALLOW_DANGEROUS") == "1"


def check_command(cmd: str) -> tuple[bool, str]:
    """(можно ли выполнять, причина отказа)."""
    cmd = (cmd or "").strip()
    if not cmd:
        return False, "пустая команда"
    if len(cmd) > MAX_CMD:
        return False, f"слишком длинная команда ({len(cmd)} > {MAX_CMD})"
    if allow_all():
        return True, ""
    for rx, why in _DENY:
        if rx.search(cmd):
            return False, f"запрещено guard: {why}"
    return True, ""


# Для действия "py" команды нет — есть код. Ловим только очевидно разрушительное:
# удаление по абсолютному пути и системные команды внутри subprocess/os.system.
CODE_DENY = [
    (re.compile(r"shutil\.rmtree\s*\(\s*[rRuUbB]{0,2}['\"](?:/|~|[A-Za-z]:[\\/])", re.I),
     "удаление по абсолютному пути"),
    (re.compile(r"os\.(?:remove|unlink|rmdir|removedirs)\s*\(\s*[rRuUbB]{0,2}['\"](?:/|~|[A-Za-z]:[\\/])", re.I),
     "удаление по абсолютному пути"),
    (re.compile(r"open\s*\(\s*[rRuUbB]{0,2}['\"](?:/|[A-Za-z]:[\\/](?:Windows|Users|Program|System))", re.I),
     "запись в системный путь"),
    (re.compile(r"(?:os\.system|subprocess\.\w+)\s*\([^)]*(?:rm\s+-rf\s+/|format\s+[a-zA-Z]:|"
                r"shutdown|taskkill\s+/f)", re.I),
     "разрушительная команда"),
]


def check_code(code: str) -> tuple[bool, str]:
    """Проверка python-кода перед запуском (действие py)."""
    code = code or ""
    if len(code) > 20000:
        return False, f"слишком длинный код ({len(code)} > 20000)"
    if allow_all():
        return True, ""
    for rx, why in CODE_DENY:
        if rx.search(code):
            return False, f"запрещено guard: {why}"
    return True, ""
