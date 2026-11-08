# QUICKSTART — 5 минут до первого результата

## 1. Один вход

```bash
python toolbox.py index        # список инструментов
python toolbox.py auto <что-то>
```

`auto` понимает и файл, и строку:

```bash
python toolbox.py auto "Q1RGe2ZsYWd9"
# [base64] CTF{flag}

python toolbox.py auto capture.pcap
# тип: PCAP, размер: 17 KB
# [i] что запустить:
#     python toolbox.py pcap capture.pcap
#     python toolbox.py creds capture.pcap
#     ...
```

## 2. Если дали файл

1. `auto` → тип и список команд.
2. `triage` → флаги, strings, base64, zip.
3. Дальше по типу:
   - PNG/JPEG → `png_chunks`, `lsb`, `exif`, `qr`;
   - ZIP/DOCX → `zipmeta`, `ooxml`, `hunt`;
   - PCAP → `pcap`, `creds`, `http`, `reasm`, `dns`;
   - ELF/PE → `checksec`, `strings`, `xor_scan`;
   - WAV → `audio`;
   - APK → `apk`;
   - образ диска → `disk`.

## 3. Если дали строку

```bash
python toolbox.py enc "...."
python toolbox.py auto "...."
```

Показывает все разумные варианты: base64, hex, base32, url, reverse, биты, десятичные
коды — без «Done».

## 3.5. Если флаг другого формата

```bash
$env:FLAG_PREFIXES="ACME,CTF"       # PowerShell, на всю сессию
python toolbox.py triage dump --flag-prefix ACME
python toolbox.py triage dump --flag-set extended
python toolbox.py triage dump --any-prefix
```

Наборы префиксов лежат в `flags.json`. По умолчанию ловятся `ctf`, `flag`,
`nto`, `innopolis`, `innoctf`, `vosh` — **без учёта регистра**. Набор
`russian` добавляет VK Cup/Tinkoff и др.; `--any-prefix` ловит любой `word{...}`.

## 4. Если дали сервис/URL

```bash
python toolbox.py param "http://host/?id=1"
python toolbox.py ssti  "http://host/?q=1"
python toolbox.py dirfuzz http://host
python toolbox.py jwtbrute "<token>" --wordlist words.txt
```

## 5. Если дали бинарник

```bash
python toolbox.py checksec ./bin
python toolbox.py strings ./bin --grep "flag|key|pass"
python reverse/xor_scan.py ./bin
python toolbox.py pypack ./app.exe
```

## 6. Если дали машину по SSH

```bash
bash linux/privesc.sh | tee privesc.txt
python toolbox.py gtfo --check "find,base64,vim"
python toolbox.py audit /usr/local/sbin/some-script --check-writable
```

## 7. Добавить свой скрипт

1. Положи файл в нужную папку.
2. Добавь строку в `REGISTRY` в `toolbox.py`:
   ```python
   ("misc", "mytool", "misc/mytool.py", "что делает"),
   ```
3. Проверь: `python toolbox.py index` и `python toolbox.py mytool --help`.

## 8. Проверка

```bash
python tests/selftest.py
```

Тесты создают временный каталог и сами его удаляют.
