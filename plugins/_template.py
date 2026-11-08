# -*- coding: utf-8 -*-
"""Шаблон плагина. Скопируй в plugins/<имя>.py и поправь match/move.

Файлы, начинающиеся с "_", кит не загружает — этот шаблон безопасен.
"""
from __future__ import annotations


def move(text: str, state: dict):
    """Что отправить сервису. None = пусть решает встроенная логика."""
    low = text.lower()
    if "привет" in low:
        return "hello"
    return None


PLUGIN = {
    "name": "template",
    "kind": "interactive",
    "match": {"banner": r"НИКОГДА_НЕ_СОВПАДЁТ"},
    "move": move,
}
