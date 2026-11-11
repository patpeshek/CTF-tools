# Toolbox

**Самый простой вход: [START.md](START.md)** — «что видишь → какую команду», одна страница без теории.

Набор небольших локальных утилит для разбора файлов, картинок, архивов, трафика и веба.
Каждый скрипт делает один шаг и запускается вручную. Всё оффлайн: сеть не используется,
внешние сервисы не вызываются.

## Дерево

```
toolbox/
├─ README.md              # этот файл
├─ MD_GUIDE.md            # навигатор по всем md: что где и когда читать
├─ INDEX.md               # таблица «инструмент → что делает → пример»
├─ GUIDE.md               # «что мне дали и что с этим делать»
├─ WEB.md                 # полный гид по веб-задачам (включая JS-консоль)
├─ QUICKSTART.md          # 5 минут до первого результата
├─ MANUAL.md              # ручная работа: то, что скрипты не делают
├─ CHEATSHEET.md          # команды по категориям
├─ EXAMPLES.md            # типовые задачи и рецепты
├─ CHANGELOG.md
├─ toolbox.py             # единый диспетчер + auto
├─ common.py              # общие helpers
├─ triage.py              # первый прогон по файлу/папке
├─ enc.py                 # декодировать строку во все стороны
├─ stego/ ...
├─ forensic/ ...
├─ network/ ...
├─ crypto/ ...
├─ linux/ ...
├─ admin/               # образы ВМ, логи, реестр/службы Windows, конфиги
├─ web/ ...
├─ pwn/ ...
├─ reverse/               # строки, XOR, упаковщики
├─ misc/
└─ tests/
```

## Быстрый старт

```bash
python toolbox.py auto suspicious_file     # что это и что запускать
python toolbox.py auto "Q1RGe2ZsYWd9"       # строка → все декодировки
python toolbox.py all --dir dump            # универсальный перебор
python toolbox.py index                    # все инструменты
```

Дальше — по подсказкам `auto`:

```bash
python toolbox.py triage suspicious_file
python toolbox.py lsb pic.png --diff pic2.png --channel r
python toolbox.py pcap capture.pcap --dump streams
python toolbox.py rsa shared --moduli mods.txt --target t --cipher 0x...
```

Проверка, что всё живо:

```bash
python tests/selftest.py
```

Если непонятно, с чего начать, или скрипт не подходит под задачу — открой `MANUAL.md`.
Полная таблица инструментов — `INDEX.md`, короткий сценарий — `QUICKSTART.md`.
Навигатор по всей документации — `MD_GUIDE.md`.
Веб-задачи — `WEB.md` (от view-source до JS в консоли).
Дали машину/контейнер/SSH — `linux/LINUX.md`.

## Что видишь в задаче → что запускать

| Симптом | Инструмент |
|---|---|
| «дан файл, непонятно что» | `triage.py` |
| строка из букв/цифр, «закодировано» | `enc.py` |
| PNG/JPEG «что-то скрыто» | `stego/lsb.py`, `stego/alpha.py`, `stego/carve.py` |
| JPEG, «внутри ещё файл» | `stego/jpeg_tail.py` |
| DOCX/XLSX, «спрятано в документе» | `stego/ooxml.py` |
| GIF/анимация | `stego/gif_frames.py` |
| «много скобок», повторы символов | `stego/runs.py` |
| ZIP/архив, «пароль», «комментарий» | `forensic/zipmeta.py` |
| образ диска, «удалённые файлы» | `forensic/disk_triage.sh` |
| образ ВМ: OVA/VMDK/QCOW2/VDI/VHD | `admin/vm_image.py` (`--raw` → raw-диск) |
| логи auth/nginx/journald/auditd, history, «кто вошёл / что сделал» | `admin/log_analyze.py` (`--timeline`) |
| фото, «где снято / когда» | `forensic/exif.py`, `misc/timeconv.py` |
| PCAP, «кто атаковал / что украли» | `network/pcap_report.py` |
| классический шифр | `crypto/classical.py` |
| «UGU ACU UUC» | `crypto/genetic.py` |
| «ничего не подходит, перебери всё» | `crypto/autocrack.py` |
| есть шифротекст и рядом «материалы» | `crypto/megacrack.py` |
| вообще непонятно, что дали | `megaall.py` |
| XOR, «ключ по маске», known prefix | `crypto/xor_known.py` |
| «пароль сгенерирован по времени» | `crypto/prng_seed.py` |
| бинарник + зашифрованный файл | `crypto/aes_file.py` |
| хеш, «подобрать пароль» | `crypto/hash_id.py` |
| cookie/token | `web/jwt_tool.py` |
| бинарник, переполнение | `pwn/ret2win.py` |
| RSA: несколько модулей n, «одна печать с ошибкой» | `crypto/rsa_tool.py shared` |
| RSA: `public.pem` + шифротекст | `crypto/rsa_tool.py auto key.pem --cipher c` |
| самодельный потоковый шифр (SHA256+nonce+counter) | `crypto/stream_sha256.py` |
| Minecraft-трафик, «расшифруй сессию» | `network/mc_decrypt.py` |
| координаты/пиксель-арт из пакетов | `network/mc_blocks.py` + `stego/bitmap_font.py` |
| UDP и самодельный протокол `SIG/.../...` | `network/udp_payloads.py` |
| Linux: sudo/SUID/cron/writable | `linux/privesc.sh`, `linux/gtfobins.py` |
| дамп ФС/конфигов: sudoers, SUID-список, cron, shadow, секреты | `admin/admin_triage.py` |
| надо запустить ELF/посмотреть поведение | `linux/wsl.py run .\chall --dir` (Arch WSL) |
| скрипт от root что-то source-ит | `linux/script_audit.py` |
| текстовые выгрузки Volatility | `forensic/volatility_text.py` |
| «найди ключ/секрет в куче файлов» | `forensic/artifact_hunt.py` |
| Android-выгрузка: XML/SQLite/логи | `forensic/android_backup.py` |
| PNG, «спрятано в текстовых чанках» | `stego/png_chunks.py` (`--fix` при битом CRC) |
| два шифротекста, один поток | `crypto/otp_reuse.py` |
| длинные DNS-метки | `network/dns_tunnel.py` |
| HTTP-объекты из PCAP | `network/pcap_http.py` |
| быстрый прогон payload'ов по URL | `web/param_probe.py` |
| подбор секрета JWT / SSTI | `web/jwt_brute.py`, `web/ssti_probe.py` |
| не знаю, что за файл | `python toolbox.py solve file` (автопилот) или `auto file` |
| защиты бинарника | `pwn/checksec.py` |
| format string | `pwn/fmtstr.py` |
| сервис «N раундов вопросов» | `pwn/oracle.py` |
| строки/XOR/упаковщик | `reverse/strings_filter.py`, `reverse/xor_scan.py`, `reverse/py_pack.py` |
| бинарник, «разбери всё» | `reverse/megarev.py` |
| креды из PCAP | `network/pcap_creds.py` |
| WAV, «спрятано в звуке» | `stego/audio_spectrum.py` |
| документ DOCX/XLSX, «внутри пусто» | `toolbox.py text`, затем `ws` |
| PDF с текстом | `toolbox.py text`, затем `ws`/`enc` |
| Brainfuck/Ook/Cow/Befunge | `stego/esolang.py` |
| Bacon/ADFGX/Bifid/base58/uuencode | `crypto/obscure.py` |
| QR на картинке | `stego/qr_scan.py` |
| APK | `forensic/apk_info.py` |
| Docker-образ (docker save) | `forensic/docker_image.py` |
| контейнер / побег | `linux/docker_audit.sh`, `linux/DOCKER.md` |
| открытый Docker API | `network/docker_api.py` |
| git-репозиторий / `.git` | `forensic/git_hunt.py` |
| профиль браузера | `forensic/browser_artifacts.py` |
| Windows dump (hives/EVTX/lnk) | `forensic/windows_triage.py` |
| куст реестра, службы, Run-ключи, задачи, PS-история | `admin/win_admin.py` |
| Office/PDF: макросы, JS | `forensic/office_docs.py` |
| облачные ключи | `forensic/cloud_creds.py` |
| Kubernetes под | `linux/k8s_audit.sh`, `network/k8s_api.py` |
| WAV: DTMF/морзе | `stego/audio_tools.py` |
| .NET/Java/Go/Rust | `reverse/lang_info.py` |
| RSA: малая d / Hastad | `crypto/rsa_tool.py wiener|broadcast` |
| RSA: утечка `dp/dq`, малый q, `n=p^k`, `e=1` | `crypto/rsa_tool.py auto` / `dp-leak` |
| ROT47 / восьмеричные коды / 𝐦𝐚𝐭𝐡-буквы / MIME | `enc.py` |
| UTF-16/32, cp1251/866/koi8, base36/58/62/85/92/100/z85/91 | `enc.py --file file` |
| флаги в `flag`, `flag.txt`, `flag_<random>` | `forensic/flag_hunt.py`, `linux/flag_hunt.sh` |
| залить скрипт на сервер / забрать файл | `linux/TRANSFER.md`, `network/serve.py` |
| AES-ECB | `crypto/aes_ecb.py` |
| hashcat по режиму | `crypto/hashcat_run.py` |
| непонятно, что это | `toolbox.py auto` |

## Что подкрутить под условие

Почти у всех скриптов есть `--help`. Самое частое:

- `lsb.py`: `--channel all|rgb|rgba|bgr|r|g|b|a` (all = R,G,B подряд + перебор остальных), `--bits 1..8`, `--order msb`, `--diff ВТОРАЯ_КАРТИНКА`.
- `alpha.py`: `--channel a`, `--only-nonzero`, `--raw` (числа вместо символов).
- `jpeg_tail.py`: `--extract out` (распакует ZIP-хвост), `--dump tail.bin`.
- `carve.py`: `--out dir` (вырежет всё, что найдёт).
- `ooxml.py`: `--extract dir` (распакует документ).
- `pcap_report.py`: `--dump dir` (сохранит TCP-потоки), `--grep слово`.
- `classical.py`: `--known ПРЕФИКС` для аффинного, `--key` для Виженера/Плейфера,
  `vigenere-crack` — подбор ключа без него.
- `rsa_tool.py`: `shared`, `batch`, `fermat`, `common-modulus`, `small-e`, `factor`.
- `mc_decrypt.py`: `--log`, `--secret`, `--dump-dir` (JSONL по направлениям).
- `bitmap_font.py`: `--export-font "ТЕКСТ"` сохраняет распознанные глифы как JSON-шрифт.
- `android_backup.py`: `--db-limit`, `--json`.
- `param_probe.py`: `--param`, `--methods`, `--cookie`, `--payload-file`.
- `checksec.py`: `--json`.
- `fmtstr.py`: `find|leak|write|scan`, `--index`, `--addr`, `--value`, `--size`;
  `scan --connect/--local`, `--deref`.
- `oracle.py`: `--connect`/`--local`, `--match`, `--expr`, `--send`/`--send-expr`,
  `--repeat`, `--until`, `--peek`, `--delay`, `--log`.
- `disasm.py`: `--interesting`, `--grep`, `--around`, `--strings`, `--all`, `--limit`,
  `--func ADDR` (одна функция до ret).
  `solve.py`: `--jobs` (параллельные шаги), `--plan`, `--deep`, `--time`, `--log`.
- `strings_filter.py`: `--utf16`, `--grep`, `--flag`, `--url`, `--path`.
- `xor_scan.py`: `--keylen`, `--known`, `--offset`, `--length`.
- `jwt_brute.py`: `--wordlist`, `--algs`, `--forge-sub`, `--role`.
- `ssti_probe.py`: `--param`, `--method`, `--list`.
- `dir_fuzz.py`: `--wordlist`, `--ext`, `--status`, `--threads`.
- `audio_spectrum.py`: `--start`, `--end`, `--freq-max`, `--peaks`.
- `qr_scan.py`: `--json`.
- `apk_info.py`: `--strings`, `--extract`.
- `aes_ecb.py`: `--hex`, `--key`, `--decrypt`, `--blocks`.
- `hashcat_run.py`: `--mode`, `--wordlist`, `--dry-run`.
- `toolbox.py auto`: понимает файл и строку, печатает рекомендации.
- `autocrack.py`: `--text/--hex/--file`, `--depth`, `--deep`, `--top`; для хешей
  `--hash/--hash-file`, `--wordlist auto|путь`, `--rules`.
- `megacrack.py`: `--cipher-file`, `--material`, `--material-dir`, `--deep`,
  `--max-tokens`, `--max-pairs`; сам собирает ключи из токенов и пар.
- `megaall.py`: `--file`, `--dir`, `--text`, `--hex`, `--deep`, `--time`,
  `--wordlist`, `--no-hash`, `--no-rsa`; без аргументов сканирует текущую папку.
- `whitespace.py`: `--mode auto|ws|bits|zw|vs|tags|braille|trail`.
- `esolang.py`: `--lang auto|bf|ook|cow|befunge|deadfish|ws`, `--input`.
- `obscure.py`: `auto`, `adfgx/adfgvx`, `bifid --period`, `porta`, `beaufort`,
  `gronsfeld`, `autokey`, `hill --matrix`.
- `megarev.py`: `--file`, `--dir`, `--out`, `--deep`, `--time`, `--json`,
  `--no-crypto`, `--min-score`, `--show-noise`.
- `docker_image.py`: `--out`, `--json`, `--dockerfile`, `--max-size`.
- `docker_audit.sh`: без аргументов, только чтение.
- `docker_api.py`: `--host`, `--list`, `--inspect`, `--logs`, `--exec --yes`.
- `git_hunt.py`: `--all-objects`, `--json`, `--max-objects`.
- `browser_artifacts.py`: `--json`, `--limit`.
- `windows_triage.py`: `--json`, `--limit` (0 = все файлы).
- `office_docs.py`: `--out`, `--json`.
- `cloud_creds.py`: `--metadata`, `--json`.
- `k8s_api.py`: `--host`, `--token`, `--ca`, `--insecure`, `--list`, `--secrets`.
- `audio_tools.py`: `--mode auto|dtmf|morse`.
- `lang_info.py`: `--json`.
- `rsa_tool.py`: `wiener --n --e --cipher`, `broadcast --e --pairs "n:c"`.
- `flag_hunt.py` / `flag_hunt.sh`: `--all`, `--pattern` (glob `*.key` или regex), `--json`; имена `flag*` и содержимое.
- `serve.py`: `--dir`, `--port`, `--bind`, `--upload`, `--token`.
- `aes_file.py`: `--key`, `--key-xor 42`, `--keylen 32`, `--iv`, `--ivlen 16`.
- `ret2win.py`: `--offset`, `--addr`, `--align`, `--remote host:port`.
- `timeconv.py`: `--tz +3`, миллисекунды определяются автоматически.
- `rsa_tool.py`: `shared --moduli|--json --target --cipher`, `common-modulus`, `small-e`.
- `stream_sha256.py`: `--key/--nonce` в hex/base64/raw, `--brute` перебирает варианты.
- `mc_decrypt.py`: `--log` (ключи из лога), `--secret`, `--dump-dir packets/`.
- `mc_blocks.py`: `--pid 66 --x0 <минимум X> --csv board.csv`; далее `bitmap_font.py --flip-y`.
- `bitmap_font.py`: `--ascii`, `--decode`, `--legend`, `--flip-x/--flip-y`, `--font`.
- `artifact_hunt.py`: `--zip`, `--context 2`, `--max-size 20`.
- `script_audit.py`: `--check-writable` — покажет, какие файлы скрипта можно подменить.

## Форматы флагов

По умолчанию ищутся префиксы `ctf` / `flag` / `nto` / `innopolis` / `innoctf` /
`vosh` — **без учёта регистра**, поэтому `NTO{...}`, `nTo{...}` и `VOSH{...}`
находятся одинаково. Если формат другой, его не надо хардкодить — он
настраивается на запуск:

```bash
# все инструменты в текущей сессии (Windows / Linux)
set FLAG_PREFIXES=ACME,CTF          # cmd
$env:FLAG_PREFIXES="ACME,CTF"       # PowerShell
export FLAG_PREFIXES="ACME,CTF"     # bash

# точечно для инструмента
python toolbox.py triage dump --flag-prefix ACME
python toolbox.py hunt dump --flag-prefix ACME
python toolbox.py autocrack --text "..." --flag-prefix ACME
python toolbox.py auto file.bin --flag-prefix ACME

# набор из flags.json (имя набора тоже без учёта регистра)
python toolbox.py triage dump --flag-set extended
python toolbox.py triage dump --flag-set RUSSIAN

# ловить вообще любой префикс вида word{...}
python toolbox.py triage dump --any-prefix
```

`flags.json` — именованные наборы: `default` (ctf/flag/nto/innopolis/innoctf/vosh),
`extended` (популярные зарубежные CTF), `russian` (NTO, InnoCTF, Innopolis, VOSH,
VK Cup, Tinkoff и др.), `custom`. Свой набор: добавь ключ со списком префиксов и
используй `--flag-set имя`. Флаг `--flag-prefix` имеет приоритет над набором и env.
Регистр в списках не важен — можно писать `NTO` или `nto`.

## Чего здесь нет

- Тяжёлых сканеров и эксплуатации (nmap, gobuster, sqlmap, Burp) — команды в `CHEATSHEET.md`.
- Тяжёлых бинарей (binwalk, foremost, zsteg, steghide) — если стоят, используй их;
  скрипты покрывают базовые случаи, когда под рукой только Python.
- Автоматического решения: каждый скрипт — один шаг, который запускаешь ты.
- `dir_fuzz.py` и `param_probe.py` — облегчённые; для больших словарей лучше ffuf/gobuster.

## Зависимости

```bash
pip install -r requirements.txt
```

Обязательно: `pillow`, `numpy`, `pycryptodome`, `scapy`, `opencv-python-headless`.
Опционально: `requests`, `pytesseract` + Tesseract (OCR), `exiftool` (системный),
`hashcat` (системный) для `hashcat_run.py`.
