# GUIDE — что мне дали и что с этим делать

Не знаешь, какой md открыть? Сначала `MD_GUIDE.md`.

Один вход, если совсем непонятно:

```bash
python toolbox.py auto <файл>
```

Он покажет тип, теги содержимого (`whitespace-only`, `zero-width`, `esolang:brainfuck`,
`encoded-blob`…) и список команд. Дальше — по таблице.

## 0. Быстрая таблица

| Что видишь | Как проверить | Чем работать |
|---|---|---|
| файл «пустой», но не 0 байт | `triage` → `whitespace-only` | `ws --mode ws` |
| в тексте невидимые символы | `triage` → `zero-width` | `ws --mode zw` |
| странные точки/кружки (Braille) | `triage` → `braille` | `ws --mode braille` |
| пробелы в конце строк | `triage` → `trailing-whitespace` | `ws --mode trail` |
| только `+-<>[].,` | `triage` → `esolang:brainfuck` | `esolang` |
| `Ook. Ook?`, `MoO`, `idso` | `triage` → `esolang:*` | `esolang` |
| длинные base64/hex | `triage` → `encoded-blob` | `auto`, `enc` |
| цифры 1–26 / A-B по 5 / 1–5 | `triage` | `obscure auto` |
| архив | `triage` | `zipmeta`, `text`, `hunt` |
| документ DOCX/XLSX | `triage` | `text`, потом `ws`/`esolang` |
| PDF | `triage` | `text`, потом `ws`/`enc` |
| картинка | `triage` | `png_chunks`, `lsb`, `exif`, `qr` |
| PCAP | `triage` | `pcap`, `creds`, `http` |

## 1. Дали документ (DOCX/XLSX/PPTX)

Документ — это zip. Не мучай Word:

```bash
python toolbox.py text document.docx --classify --out doc.txt
python toolbox.py triage document.docx
```

`text` вытащит текст из `word/document.xml` (теги срежет, пробелы/табы/zero-width
оставит). Дальше:

```bash
python toolbox.py ws doc.txt                 # авто: ws / zw / braille / trail
python toolbox.py esolang doc.txt            # если внутри BF/Ook/…
python toolbox.py enc "$(cat doc.txt)"       # если внутри строка
```

Если `triage` пишет `whitespace-only` — это Whitespace, запускай `ws --mode ws`.
Если `zero-width` — `ws --mode zw`. Если `esolang:brainfuck` — `esolang`.

## 2. Дали PDF

```bash
python toolbox.py text document.pdf --classify --out doc.txt
python toolbox.py triage document.pdf
```

Дальше так же: `ws`, `esolang`, `enc`, `obscure`. Если текст не извлёкся —
PDF может быть сканом: `triage` покажет картинки, дальше OCR/`png_chunks`.

## 3. Дали архив

```bash
python toolbox.py triage archive.zip
python toolbox.py text archive.zip --out all.txt
python toolbox.py hunt archive.zip --zip
```

- `zipmeta` — комментарии и имена;
- `text` — текст из вложенных xml/txt;
- `hunt` — ключи/секреты/флаги;
- если внутри бинарники — они попадут в `triage`/`megaall`.

## 4. «Файл выглядит пустым»

1. `python toolbox.py triage file`
2. Если `whitespace-only`:
   ```bash
   python toolbox.py ws file --mode ws
   ```
   Не выполнилось — попробуй `--mode bits` (space=0, tab=1).
3. Если `zero-width` / `braille` / `variation` — соответствующий `--mode`.
4. Если ничего — `python toolbox.py enc "$(cat file)"`.

## 5. Дали строку/текст без файла

```bash
python toolbox.py auto "...."
python toolbox.py enc "...."
python toolbox.py obscure auto --text "...."
```

`auto`/`enc` — кодировки; `obscure` — Bacon, ADFGX, Bifid, base58, tap code и т.п.

## 6. Куда «писать» и как не запутаться

- Всё, что вытащил, сохраняй в файл: `--out extracted.txt`.
- Дальше передавай **этот файл** инструменту, а не исходный документ.
- Проверяй теги повторно: `python toolbox.py triage extracted.txt`.
- Если инструмент просит `--text`, передавай строку в кавычках; если `--file` — путь.

## 7. Если совсем ничего не сходится

```bash
python toolbox.py all --dir .
```

`megaall` сам разложит файлы/архивы/строки на артефакты, найдёт кандидатов в
шифротекст, ключи, хеши и прогонит перебор.

## 8. Веб

Отдельный большой гайд: `WEB.md` — от `robots.txt` и view-source до SQLi, XSS,
JWT, SSRF, SSTI, десериализации и готовых JS-команд для консоли (даже если JS
ты не знаешь).

## 9. Дали машину / контейнер / SSH

`linux/LINUX.md` — что делать после входа: `sudo -l`, SUID, capabilities, cron,
записываемые конфиги, docker.sock, k8s, где искать флаг. SSH-подключение —
`linux/SSH.md` (внешний `ssh`, ProxyCommand/openssl s_client, туннели).
Флаги в `flag`/`flag.txt`/`flag_<random>` — `linux/flag_hunt.sh` и
`forensic/flag_hunt.py`. Как залить скрипт на сервер — `linux/TRANSFER.md`.
