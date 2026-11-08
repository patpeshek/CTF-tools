# Плагины

Плагин — обычный `.py` в этой папке с одним словарём `PLUGIN`. Кит сам
находит файлы (кроме `_*`), поэтому не нужно ничего регистрировать.

```python
PLUGIN = {
    "name": "my-thing",                 # короткое имя
    "kind": "interactive",              # "interactive" или "file"
    "match": {"banner": r"добро пожаловать"},   # для interactive
    # "match": {"file": r"\.pcap$", "ext": [".pcap"]},  # для file
    "move": move,                       # interactive(text, state) -> str|None
    # "run": run,                       # file(path, opts) -> dict
}
```

## interactive

```python
def move(text: str, state: dict):
    """Вернуть, что отправить сервису (без \\n), или None."""
    if "нажми q" in text.lower():
        return "q"
    return None
```

`state` между вызовами: `last`, `round`, `history`, `flags`. Можно хранить
своё — это обычный dict.

Проверить: `python misc/game_bot.py --connect h:p --plugins-dir . --list-plugins`.

## file

```python
def run(path: str, opts: dict):
    """Вернуть {"flags": [...], "notes": [...], "plan": [...]}."""
    data = open(path, "rb").read()
    return {"flags": [], "notes": [f"{len(data)} байт"], "plan": []}
```

Файловые плагины вызываются вручную или из `auto` (подсказкой), чтобы не
ломать штатный разбор.

## Правила

- Не запускать то, что пришло из задачи, без нужды.
- Не печатать чужие флаги в чат (только «найден»).
- Не тянуть сеть без явного флага.
- Не маскировать ошибку: если не понял — вернуть `None`, а не «наверное так».
