# Корпус настоящих задач (corpus bench)

Не синтетика, а реальные задачи прошлых CTF: файлы, которые выдавали игрокам,
и эталонные флаги из официальных репозиториев. Нужен, чтобы честно измерять
«кит решает задачи», а не «кит запускается без ошибок».

## Что внутри

| Источник | Репозиторий | Задач с файлами |
|---|---|---|
| BCACTF 5.0 (2024) | `github.com/BCACTF/bcactf-5.0` | 25 |
| BCACTF 4.0 (2023) | `github.com/BCACTF/bcactf-4.0` | 29 |
| BCACTF camp 2023 | `github.com/BCACTF/camp-2023` | 9 |

Коммит BCACTF 5.0, с которого снят корпус:
`0bda7285e7ff79e4180ed657b76467a8d9023b16`.

Файлы лежат в:

- `F:\AIproject\ctf-files\BCACTF\2024` — задачи BCACTF 5.0 (как их выдавали);
- `F:\AIproject\ctf-files\corpus\<event>\<task>` — распакованные вручную
  BCACTF 4.0 и camp 2023: **только выданные файлы**, без `flag.txt`,
  `solve.txt`, `gen.py` и прочих спойлеров.

`manifest.json` — список задач: путь, категория, баллы, эталонный флаг
(в отчётах маскируется), причина пропуска для сервисных задач.

## Как запускать

```powershell
python tests/corpus_bench.py --list
python tests/corpus_bench.py                        # весь корпус
python tests/corpus_bench.py --category crypto
python tests/corpus_bench.py --only xor,chalkboardgag --timeout 120
python tests/corpus_bench.py --deep --jobs 2 --json out.json
```

Каждая задача запускается как `python toolbox.py solve <файл> --time N
--any-prefix`; PASS — если в выводе есть эталонный флаг. `NEAR` — флаг
распознан почти точно (OCR/PDF исказили символы, сходство ≥ 0.80): это
«текст виден, нужен глаз человека», а не провал.

## Статусы

- **PASS** — флаг найден автоматически и совпал с эталоном.
- **NEAR** — найдено почти-флаг (OCR-ошибки). Требует подтверждения глазами.
- **FAIL** — инструменты отработали, флага нет.
- **TIMEOUT** — не уложились в бюджет.

Сервисные задачи (pwn/web/remote-jail/crypto-оракул) в прогон не попадают:
для них нужен запущенный сервис, а не файл. Они помечены `skip` в манифесте.

## Результаты

Смотреть `latest.md` (обновляется прогоном) и `CHANGELOG.md` кита.
