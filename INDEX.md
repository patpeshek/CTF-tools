# INDEX — что где лежит

Запуск: `python toolbox.py <имя> ...` или напрямую `python <путь> ...`.
`python toolbox.py index` печатает этот список в консоль.

Гайды: `MD_GUIDE.md` (что читать), `GUIDE.md` (что дали и что делать),
`WEB.md` (веб целиком), `linux/LINUX.md` (машина/контейнер/SSH),
`MANUAL.md` (ручная работа), `CHEATSHEET.md` (команды), `EXAMPLES.md` (рецепты).

## База

| Имя | Что делает | Пример |
|---|---|---|
| `solve` | автопилот: сам выбирает шаги по типу, идёт до первого флага | `python toolbox.py solve file.bin` |
| `hint` | разбор с объяснением «что вижу → на что похоже → почему» | `python toolbox.py hint file.bin` |
| `auto` | сам смотрит файл: тип, вложенные сигнатуры, флаги, архивы, DNS, WAV, защиты; даёт план команд | `python toolbox.py auto capture.pcap` |
| `all` | универсальный перебор: файлы/папки/строки, known-plaintext XOR по префиксу флага | `python toolbox.py all dump.bin` |
| `triage` | первый прогон: тип, флаги, strings, base64, zip | `python toolbox.py triage dump/` |
| `text` | вытащить текст из DOCX/PDF/ZIP | `python toolbox.py text doc.docx --out doc.txt` |
| `enc` | base64/32/36/85/ascii85/92/100/z85/hex/url/rot13/47/18/NFKC/octal/MIME; **все кодеки** (utf-16/32, cp1251/866, koi8, latin-1) | `python toolbox.py enc "Q1RGe2ZsYWd9"` / `--file utf16.txt` |

## Stego

| Имя | Что делает | Пример |
|---|---|---|
| `lsb` | LSB канала/бит, diff двух картинок | `python toolbox.py lsb a.png --diff b.png --channel r` |
| `alpha` | значения канала как ASCII | `python toolbox.py alpha a.png --channel a` |
| `jpeg_tail` | хвост после JPEG → ZIP | `python toolbox.py jpeg_tail a.jpg --extract out` |
| `carve` | вырезать вложенные файлы по сигнатурам | `python toolbox.py carve a.bin --out out` (ZIP режется по EOCD) |
| `ooxml` | DOCX/XLSX как ZIP | `python toolbox.py ooxml a.docx --extract out` |
| `gif_frames` | пиксель с каждого кадра | `python toolbox.py gif_frames a.gif 228 69` |
| `runs` | серии символов → ASCII | `python toolbox.py runs a.txt --chars "<>{}"` |
| `png_chunks` | чанки PNG, CRC/IHDR, `--fix`, хвост | `python toolbox.py png_chunks a.png --fix fixed.png` |
| `bitmap_font` | точки → картинка → глифы | `python toolbox.py bitmap_font pts.csv --flip-y --decode` |
| `ws` | Whitespace + zero-width + braille + хвосты | `python toolbox.py ws file.txt` |
| `esolang` | Brainfuck/Ook/Cow/Befunge/Deadfish | `python toolbox.py esolang file.bf` |
| `audio` | спектрограмма WAV + пики | `python toolbox.py audio a.wav --peaks` |
| `audiotools` | DTMF и морзе из WAV (проверка `.-` через `--raw`, код в нижнем регистре) | `python toolbox.py audiotools a.wav --raw` |
| `qr` | найти и прочитать QR | `python toolbox.py qr a.png` |

## Forensic

| Имя | Что делает | Пример |
|---|---|---|
| `zipmeta` | комментарии/extra ZIP | `python toolbox.py zipmeta a.zip --decode` |
| `exif` | метаданные | `python toolbox.py exif photo.jpg` |
| `disk` | образ диска: mount/photorec/LUKS | `sudo bash forensic/disk_triage.sh disk.img` |
| `hunt` | ключи/секреты/флаги в файлах и zip | `python toolbox.py hunt dump --zip` |
| `android` | XML/SQLite/логи Android | `python toolbox.py android dump --json out.json` |
| `vol` | pstree/envars | `python toolbox.py vol envars.txt --name agent` |
| `apk` | APK: файлы, manifest, строки | `python toolbox.py apk app.apk --extract out` |
| `ipa` | iOS IPA: Info.plist, строки, флаги | `python toolbox.py ipa app.ipa --out app` |
| `geo` | геолокация по фото: EXIF/GPS + ссылки | `python toolbox.py geo photo.jpg --json report.json` |
| `docker` | Docker-образ: слои, whiteouts, секреты | `python toolbox.py docker image.tar --out fs` |
| `git` | git: история, секреты, удалённые файлы | `python toolbox.py git repo --all-objects` |
| `browser` | история/куки/логины браузера | `python toolbox.py browser "Chrome/User Data"` |
| `win` | Windows-артефакты: Run/URL/пути | `python toolbox.py win dump` |
| `office` | Office/PDF: макросы, JS, вложенное | `python toolbox.py office doc.docx --out out` |
| `cloud` | AWS/GCP/Azure ключи и metadata | `python toolbox.py cloud dump --metadata` |
| `flaghunt` | файлы-флаги по имени/содержимому | `python toolbox.py flaghunt dump` |

## Network

| Имя | Что делает | Пример |
|---|---|---|
| `pcap` | сводка по PCAP | `python toolbox.py pcap cap.pcap --max-packets 5000` |
| `reasm` | сборка TCP по seq | `python toolbox.py reasm cap.pcap --dump streams` |
| `mc` | Minecraft AES-CFB8 + пакеты | `python toolbox.py mc cap.pcap --log latest.log` |
| `mcblocks` | блоки → CSV | `python toolbox.py mcblocks cap.pcap --log latest.log --csv b.csv` |
| `udp` | UDP payload/протокол | `python toolbox.py udp cap.pcap --sep /` |
| `icmp` | ICMP payload, поля заголовка, тайминги | `python toolbox.py icmp cap.pcap` |
| `dns` | DNS-канал: индексы, порядок, ключ из env-артефактов, XOR→zlib | `python toolbox.py dns cap.pcap` / `--seed S --host H` |
| `http` | HTTP-объекты | `python toolbox.py http cap.pcap --out objs` |
| `creds` | креды из трафика | `python toolbox.py creds cap.pcap` |
| `dockerapi` | открытый Docker API | `python toolbox.py dockerapi --host http://ip:2375 --list` |
| `k8sapi` | Kubernetes API по токену | `python toolbox.py k8sapi --host https://ip:6443 --token T --list` |
| `serve` | HTTP-сервер: раздача и приём файлов | `python toolbox.py serve --dir . --port 8000 --upload` |

## Crypto

| Имя | Что делает | Пример |
|---|---|---|
| `autocrack` | перебор кодировок, Цезаря, аффинного, XOR, rail, Виженера; хеши | `python toolbox.py autocrack --hex ... --deep` |
| `autocrack` | перебрать кодировки/шифры/XOR/хеши | `python toolbox.py autocrack --hex ...` |
| `mega` | шифротекст + материалы → перебор ключей/шифров; без материалов объясняет, что дать | `python toolbox.py mega enc.bin --material-dir dump` |
| `obscure` | Bacon/ADFGX/Bifid/Porta/Hill/base58/… | `python toolbox.py obscure auto --text ...` |
| `classical` | классические шифры + `vigenere-crack` | `python toolbox.py classical vigenere-crack --text "..."` |
| `genetic` | триплеты → аминокислоты | `python toolbox.py genetic "UGUACUUUC"` |
| `xorknown` | XOR с known plaintext; длину ключа подбирает сам | `python toolbox.py xorknown enc.bin --known "CTF{"` |
| `prng` | random по seed | `python toolbox.py prng --ts "2026-01-01 12:00:00"` |
| `aes` | AES-CBC из бинарника | `python toolbox.py aes f.enc --auto --from-bin encryptor` |
| `ecb` | детект/расшифровка ECB | `python toolbox.py ecb c.hex --hex --key K --decrypt` |
| `hash_id` | тип хеша | `python toolbox.py hash_id 5f4dcc...` |
| `hashcat` | подбор пароля: авто-режим, словарь/маска/правила, реальный запуск если hashcat установлен | `python toolbox.py hashcat <hash> --attack 3 --mask "?d?d?d?d"` |
| `rsa` | gcd/Ферма/малая e/Винер/CRT/dp-утечка/smallq/p^k/PEM + `auto`: числа из текста, ключи, все атаки | `python toolbox.py rsa auto task.txt` |
| `otp` | two-time pad | `python toolbox.py otp --c1 ... --c2 ... --crib "the "` |
| `stream` | SHA256-поток XOR | `python toolbox.py stream --cipher ... --key ... --nonce ... --brute` |

## Blockchain

| Имя | Что делает | Пример |
|---|---|---|
| `evm` | EVM calldata: селектор, аргументы, raw-слова | `python toolbox.py evm 0xa9059cbb...` |
| `evm --sig` | посчитать селектор по сигнатуре | `python toolbox.py evm --sig "transfer(address,uint256)"` |

## AI/ML

| Имя | Что делает | Пример |
|---|---|---|
| `pickle` | pickle/модели: опасные глобалы, строки, флаги (без запуска) | `python toolbox.py pickle model.pkl` |

## Linux

| Имя | Что делает | Пример |
|---|---|---|
| `privesc` | разведка прав | `bash linux/privesc.sh` |
| `docker` (linux) | аудит контейнера | `bash linux/docker_audit.sh` |
| `k8s` | аудит пода Kubernetes | `bash linux/k8s_audit.sh` |
| `flaghunt` (linux) | поиск файлов-флагов | `bash linux/flag_hunt.sh` |
| `gtfo` | GTFObins | `python toolbox.py gtfo --check find,base64` |
| `wsl` | запуск ELF в Arch WSL (gdb/pwntools), файлы в `~/inbox` | `python linux/wsl.py run .\chall --dir` / `wsl.py inbox` / `--arch auto` |
| `audit` | что source-ит root-скрипт | `python toolbox.py audit /usr/local/sbin/x --check-writable` |

## Web

| Имя | Что делает | Пример |
|---|---|---|
| `jwt` | decode/forge JWT | `python toolbox.py jwt auto <token> --wordlist w.txt` |
| `jwtbrute` | подбор секрета | `python toolbox.py jwtbrute <token> --wordlist w.txt` |
| `ssti` | поиск SSTI | `python toolbox.py ssti "http://h/?q=1"` |
| `param` | payload'ы по параметрам (SQLi/XSS/траверсал) + поиск флага в ответах | `python toolbox.py param "http://h/?q=0"` |
| `dirfuzz` | перебор директорий | `python toolbox.py dirfuzz http://h` |

## PWN

| Имя | Что делает | Пример |
|---|---|---|
| `checksec` | защиты ELF/PE | `python toolbox.py checksec ./bin` |
| `ret2win` | паттерн/оффсет/payload | `python toolbox.py ret2win payload --offset 80 --addr 0x4011a2` |
| `fmtstr` | format string helper: payload'ы + `scan` по живому сервису | `python toolbox.py fmtstr auto --connect h:p` |
| `oracle` | TCP-сервис: вопрос → формула → ответ, N раундов | `python toolbox.py oracle --connect h:1 --auto` (или `--preset coprime`) |
| `ppc` | разбор PPC-вопроса: какие стратегии и ответы видит движок (арифметика, хеши md5/sha/crc32, модулярка — обратный/CRT/`n! mod m`/`Fib mod m`/`C(n,k) mod p`, простота по Miller–Rabin, графы — путь/компоненты/топосорт, матрицы, скобки, k-й/медиана) | `python toolbox.py ppc "md5 of 'hello'"` |

## Reverse

| Имя | Что делает | Пример |
|---|---|---|
| `strings` | строки с фильтрами | `python toolbox.py strings bin --grep "flag|key"` |
| `megarev` | тип/защиты/упаковщик/строки/вложенные/ключи/перебор | `python toolbox.py megarev bin` |
| `disasm` | дизасм x86/x64/arm64: сравнения, константы, ссылки на строки | `python toolbox.py disasm bin --interesting` |
| `ghidra` | headless-декомпиляция Ghidra в C-подобный текст | `python toolbox.py ghidra bin --out dump.c` |
| `lang` | .NET/Java/Go/Rust/Electron | `python toolbox.py lang app.exe` |
| `xorscan` | XOR-скан файла | `python toolbox.py xorscan bin --keylen 8` |
| `pypack` | PyInstaller/pyarmor/Nuitka | `python toolbox.py pypack app.exe` |

## Misc

| Имя | Что делает | Пример |
|---|---|---|
| `time` | unix ↔ дата | `python toolbox.py time --ts 1274552191` |
| `game` | универсальный бот: вопрос / Wordle / клавиши / поле + флаг | `python toolbox.py game --connect h:p --auto` |
| `wordle` | Wordle: фильтр кандидатов + энтропия | `python toolbox.py wordle play --connect h:p` |
| `formats` | память незнакомых разметок (`Г Ж С`, `1 2 0`) | `python toolbox.py formats --list` |
| `ocr` | текст с картинки/кадра: капча, скриншот, флаг на фото | `python toolbox.py ocr pic.png --variants` |
| `video` | кадры MP4/GIF: OCR, отличия между кадрами | `python toolbox.py video clip.mp4 --every 5` |
| `nearlines` | 100000 почти одинаковых строк: уникальные и отличия | `python toolbox.py nearlines file.txt` |
