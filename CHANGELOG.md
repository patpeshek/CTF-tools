# CHANGELOG

## 2026-11-09 — 0.46

- **Корпус реальных задач + стенд `tests/corpus_bench.py`.** BCACTF 5.0 (2024),
  BCACTF 4.0 (2023), BCACTF camp 2023: 63 задачи с файлами (rev/crypto/foren/
  misc), эталонные флаги из официальных репозиториев. В отчёте флаги
  маскируются. Статусы PASS / NEAR (OCR исказил символы) / FAIL / TIMEOUT,
  сводка по категориям, сервисные задачи помечены `skip`.
- **`solve` распаковывает архивы сам:** xz/lzma, bz2, gzip, zstd, lz4, tar.
  План строится уже для внутреннего файла (`flag.wav.xz` → wav → morse/DTMF,
  `traffic.pcapng.xz` → pcap → http/dns). Раньше такие файлы были «unknown».
- **`solve` режет вложенное рекурсивно и по типу:** после `carve` внутренний
  файл разбирается своим планом (pcap → трафик, png → OCR, exe → строки), а не
  тремя универсальными шагами. `carve` выучил pcapng/pcap/mp3/ogg/flac/wasm и
  точные границы PNG/JPEG/GIF (IEND/EOI/terminator), поэтому вложенная картинка
  больше не обрезается на ложной сигнатуре.
- **Новые инструменты:**
  - `misc/ocr.py` — текст с картинки/кадра (Tesseract, несколько режимов);
    `--variants` даёт кандидатов с исправлением типичных ошибок OCR;
  - `misc/video.py` — кадры MP4/GIF через OpenCV, OCR, `--diff` по кадрам;
  - `misc/nearlines.py` — «100000 одинаковых строк»: уникальные строки и
    изменённые символы в порядке файла (классика foren/misc).
- **`common`:** сигнатуры XZ/BZ2/ZSTD/LZ4/WASM/FLAC/MP4 (ftyp); проверка
  префикса флага (мусор вида `qm8h{...}`/`ssGP_{...}` больше не принимается за
  флаг); lookbehind, чтобы `bcactf{...}` не распознавался как `ctf{...}`;
  варианты флага из PDF (пробел → `_` и пробел → ничего).
- **`solve` показывает полезный текст** (OCR, кадры, nearlines), а не только
  «шаг выполнен»; строки-кандидаты `[?]` не считаются подтверждённым флагом.
- **`solve` учитывает BF/Ook с входом:** если рядом лежит короткая строка,
  эзотерическая программа запускается с ней как с входом.
- **ODF/EPUB** (`.odp/.ods/.odt/.epub`) обрабатываются как ZIP.
- **Каталог задач Иннополис Open 2021/22–2025/26:** 83 задачи, разбор по
  категориям — `notes/innopolis-materials/tasks-catalog.md`.

## 2026-11-08 — 0.45

- **`pwn/ppc_solvers.py` — библиотека решателей PPC.** ~25 типов: цепочки
  выражений (приоритеты, `round to zero`), недостающий оператор, простые,
  НОД/НОК, делители, факториал, Фибоначчи, цифры, строки (реверс, гласные,
  слова, палиндром), сортировка, последовательности, системы счисления,
  степени/модули, даты, base64/hex, замена/подсчёт подстроки, логика,
  среднее/мин/макс/сумма, OCR base64-капч (pytesseract), BFS-лабиринт.
  Ключевые слова на русском и английском; ответы выдаются списком гипотез.
- **`oracle --auto` и `game_bot` используют эти гипотезы**: серия успехов →
  закрепление, обрыв/«wrong» → следующая гипотеза. `game_bot` научился
  угадайке бинарным поиском («больше/меньше»), BFS-лабиринту и OCR-капчам.
- **`tests/ppc_bench.py` — локальный стенд:** 21 настоящий TCP-сервис
  (RU/EN, обрыв на ошибке, флаг в конце). Результат: **21/21**.
- **`START.md`** — простая страница «что видишь → какую команду» для каждой
  категории, без теории. **`PPC.md`** — таксономия PPC-задач, как движок
  понимает вопрос, что покрыто и чего не хватает.
- Реестр: `python toolbox.py ppc "<вопрос>"` показывает, какие стратегии и
  ответы видит движок (отладка новых типов).
- **Флаги:** в потоке ловится незнакомый префикс (`NPC{...}` и любой
  `ABC{...}`), `npc` добавлен в набор по умолчанию.
- Тестов: **173** (+3: батарея PPC-вопросов, BFS-лабиринт, угадайка).

## 2026-11-08 — 0.44

- **`common.FlagGrabber` — флаг забирается всегда.** Копит хвост потока,
  снимает ANSI-раскраску и zero-width, ловит флаг, разорванный на два `recv`,
  и base64-обёртку. Подключён в `oracle` (обычный и `--auto`), `fmtstr`,
  `game_bot`, `wordle_bot` — то есть во всех местах, где читается ответ сервиса.
- **`misc/game_bot.py` — универсальный движок для интерактивных задач**, не
  только PPC: сам определяет, что перед ним — вопрос (числа/простые/гласные/
  base64/эмодзи), Wordle, «нажми клавишу»/гонка со стаминой или поле/сетка.
  Держит серию успехов, после обрыва меняет гипотезу, чужой формат пишет в
  `--record` и не делает вид, что понял.
- **Плагины `plugins/`**: обычный `.py` с `PLUGIN = {name, kind, match,
  move|run}`. Автоподбор по баннеру сервиса (`--plugins-dir`), список —
  `python toolbox.py plugins`. API и шаблон — `plugins/README.md`,
  `plugins/_template.py`.
- **`misc/wordle_bot.py`**: фильтр кандидатов по правилам Wordle (с повторами),
  выбор слова по энтропии, режимы `play`/`dry`/`assist`. Разметка:
  эмодзи, ANSI-цвета, HTML, `GYB`, «быки/коровы» и **буквы под словом**
  (`Г`/`Ж`/`С`, `Б`/`К`/`Н`; переопределяются `WORDLE_GREEN/YELLOW/GRAY`).
- **`common.Screen`** — мини-эмулятор терминала: `\r`, `\b`, очистка экрана,
  курсор (`CSI H/A/B/C/D/K/J`). `game_bot` всегда работает с отрисованным
  экраном, а не с сырым чанком: так ловятся игры, которые перерисовывают
  одно окно (почти все PPC-игры), а не печатают новую строку.
- **`misc/formats.py`** — память форматов: незнакомый набор символов разметки
  (`Г Ж С`, `2 1 0`, любые другие) спрашивается один раз и кэшируется в
  `formats.json`; дальше применяется молча.
- **`game_bot --explore`** — для совсем незнакомого экрана: по очереди шлёт
  клавиши и показывает, какие меняют состояние (`w — меняет`, `a — нет`).
- Словари: `F:\dev\wordlists\russian5.txt` (25 653 слова по 5 букв) и
  `english5.txt` (14 855 слов Wordle).
- Тестов: **170** (+11: FlagGrabber, разбор типов, Q&A, Wordle, клавиши,
  плагин, буквенные маркеры, перерисовка экрана).

## 2026-11-08 — 0.43

- **`oracle --auto` — турнир стратегий для незнакомых PPC-сервисов.**
  Вопрос классифицируется (числа / взаимно простые / простые / арифметика /
  гласные-согласные / слова / reverse / base64-hex / эмодзи / текст), берётся
  самая вероятная гипотеза ответа. Если сервис принял `--promote` раундов
  подряд (по умолчанию 10) — стратегия закрепляется за классом. Если обрыв или
  «wrong» — гипотеза помечается неудачной, переподключение и следующая.
  `--dump` сохраняет все вопросы, `--attempts`/`--rounds`/`--time` ограничивают
  перебор. Незнакомый вопрос не угадывается: печатается и сохраняется.
- Тестов: **159** (+3: promote на 10-м раунде, смена гипотезы после обрыва,
  гласные/согласные).

## 2026-11-08 — 0.42

Под прогноз задач Innopolis Open (разбор — `F:\AIproject\notes\innopolis-open-forecast-2026-11.md`).

- **`oracle --preset`**: `coprime`, `prime`, `calc`, `vowels`, `sum` — типовые
  сервисные раунды одной командой (два числа → YES/NO за 2 с и т.п.).
- **`fmtstr auto`**: перебирает `%1..%N$s` на новом соединении на каждый
  индекс, отсекает мусор, ищет флаг и строки окружения. Закрывает класс
  «флаг в памяти сервиса» (format string).
- **`aes --auto --from-bin`**: тянет строки из бинарника, пробует их как
  ключ/IV, их md5/sha1/sha256, дополнение повтором/нулями, CBC (нулевой IV,
  первые 16 байт, md5) и ECB; сортирует по «текстовости», флаг первым.
- **`jwt auto`**: decode + `alg:none` + подбор HMAC-секрета по мини-списку и
  словарю + подмена claim (`role`/`is_admin`/`sub`) с готовым токеном.
- **`carve`**: ZIP режется по EOCD (а не по следующей сигнатуре), поэтому
  распаковывается даже с мусором после архива; добавлены `tar` и `PE`,
  авто-распаковка и перебор типовых паролей.
- **`wsl.py run --arch auto`**: определяет aarch64/ARM по `e_machine` и
  запускает через `qemu-aarch64`/`qemu-arm` (с поиском сисколла в
  `/usr/aarch64-linux-gnu`); если сисколла нет — внятная подсказка, а не
  трейсбек.
- Тестов: **156** (+6: oracle preset, fmtstr auto, aes auto, jwt auto,
  carve по EOCD, `wsl.py --arch`).

## 2026-11-08 — 0.41

- **Полировка WSL:** почищен мусор (`~/.cache/paru` 343 МБ, `go-build` 758 МБ,
  `pip cache`), сделан `fstrim` (83 ГиБ), home 1.4 ГБ → 555 МБ.
- `~/.config/paru/paru.conf`: `SudoLoop`, `BatchInstall`, `CleanAfter`,
  `CombinedUpgrade`, `BottomUp` (кэш сборок не растёт).
- `~/.vimrc` (нумерация, 4 пробела, поиск, undofile), история bash 50k,
  `HISTCONTROL=ignoreboth:erasedups`, алиасы `..`, `ports`, `sz`, `ffufc`,
  `LESS=-R -F -X`.
- `.wslconfig`: добавлен `defaultVhdSize=100GB` — будущие импорты тоже с
  потолком 100 ГБ. Проверено: ключ принимается без предупреждений.
- Sparse-vhdx не включён: WSL разрешает его только с `--allow-unsafe`
  (риск порчи диска), а файл и так 16 ГБ при потолке 100 ГБ.
- Аудит-скрипт `F:\dev\wsl\setup\40-audit.sh` (диск, монтирования, конфиги,
  шелл, инструменты, pacman/paru) — быстрый health-check.

## 2026-11-08 — 0.40

- **Диск WSL ограничен 100 ГБ.** Штатный shrink невозможен (ext4 нельзя
  уменьшать на смонтированном корне, `wsl --manage --resize` умеет только
  расти), поэтому система пересобрана: новый ext4 на 100 ГБ → `rsync` →
  `qemu-img` в vhdx → `wsl --import-in-place`. Старый диск лежит в
  `F:\dev\wsl\backup\ext4-old.vhdx`.
- **`C:` больше не виден из WSL вообще.** Из `F:` смонтированы только
  `F:\dev` и `F:\AIproject` (rw); остальной `F:` — ни читать, ни писать.
- **Файлы не надо никуда переносить руками:** `python linux/wsl.py run <путь>`
  копирует бинарь в Linux через stdin в `~/inbox`, `--dir` — весь каталог.
  Новая команда `python linux/wsl.py inbox` показывает, что уже перенесено.
- **Boot-хук** `/usr/local/sbin/wsl-boot.sh` через `[boot] command` повторяет
  `mount -a` до 10 раз: на раннем старте 9p-сервер Windows ещё не готов, иначе
  папки оставались несмонтированными.
- interop выключен, systemd выключен, `vmIdleTimeout=60s` — WSL не висит в фоне.

## 2026-11-08 — 0.39

- **ffuf 2.3.0** поставлен в WSL — оригинал с `github.com/ffuf/ffuf` (пакет
  `ffuf-bin`; в репах Arch его нет, AUR отдаёт). Плюс `steghide`, `whatweb`,
  `android-apktool` (APK), `ligolo-ng`, `python-certipy-nxc`. Итого 741 пакет,
  22 AUR.
- **WSL ограничен по доступу:** смонтированы только `F:\dev` → `/mnt/f/dev`
  и `F:\AIproject` → `/mnt/f/AIproject` (rw); `C:` не виден вообще, interop
  выключен (`cmd.exe` из Linux не запускается). Пути для кита не изменились.
- **WSL не висит в фоне:** `systemd=false`, `vmIdleTimeout=60000` — после
  последней команды дистрибутив останавливается, VM гаснет. Проверено:
  `wsl -l -v` → `Stopped`, процесса `vmmem` нет.
- Полировка: `pacman` (Color, ILoveCandy, `ParallelDownloads = 10`,
  VerbosePkgLists), `~/.config/fastfetch/config.jsonc`, `~/.inputrc`,
  bash-completion, `~/wordlists` → `/mnt/f/dev/wordlists`, gdb через gef.
- Грабли: в `/etc/fstab` путь `F:\dev` не работает (backslash — escape),
  нужен `F:/dev`.

## 2026-11-08 — 0.38

- **WSL-дистрибутив Arch** поставлен на `F:\dev\wsl\archlinux` (vhdx, не на `C:`).
  Память VM 8 ГБ, 8 потоков, swap 4 ГБ на `F:` (`.wslconfig`). Пользователь
  `ctf`/`ctf`, sudo без пароля (локальная песочница), systemd включён.
- **Новый инструмент `linux/wsl.py`** — запуск ELF с Windows:
  `info` (что внутри), `run` (копирует файл или `--dir` каталог в `~/run`,
  ставит `+x`, запускает с аргументами), `sh` (любая команда), `which`,
  `install`. Закрывает ограничение «ELF не запускаются»: теперь есть gdb,
  pwntools, checksec, qemu-user, radare2, ghidra.
- Ошибка (и фикс): `wsl --manage --move` на Windows упал с
  `ERROR_SHARING_VIOLATION`, потом `E_ACCESSDENIED`, но успел создать vhdx на
  `F:`; регистрация осталась на старом пути. Лечение: `wsl --unregister` +
  `wsl --import-in-place <distro> <vhdx>`.
- Пакеты ставятся идемпотентными скриптами `F:\dev\wsl\setup\01..03`:
  фильтр `pacman -Si` (иначе одна опечатка отменяет всю транзакцию),
  `paru-bin` как AUR-хелпер (без сборки rust), fastfetch на старте и на `clear`.

## 2026-11-08 — 0.37

- **`enc` стал универсальным декодером.** `--file` теперь читается как байты:
  перебираются кодеки `utf-8/16/32 (le/be, BOM)`, `cp1251/1252/866`, `koi8-r/u`,
  `iso8859-5`, `mac_cyrillic`, `latin-1`, `utf-7`; результат фильтруется по
  печатности и наличию ASCII/кириллицы/CJK. Любой байтовый кандидат от
  base/hex/… тоже прогоняется через кодеки.
- **Больше base:** base36, z85, base92 и base100 (эмодзи), плюс уже бывшие
  16/32/32hex/58/62/64/85/ascii85/91. Всё считается за миллисекунды, флаг
  находится, если он внутри.
- **`solve`:** для короткого бинарного блоба добавлен шаг `enc --file`, поэтому
  UTF-16/32 и редкие base теперь ловятся автопилотом (проверено на
  `CTF{solve_utf16}` в UTF-16LE).
- Тесты: +8 (utf-16le/32le/cp1251/base36/z85/base92/base100, solve utf-16).

## 2026-11-08 — 0.36

Исследование похожих проектов (клоны в `F:\AIproject\_scratch\research`, коммиты
проверены, их установщики не запускались):

- `RsaCtfTool/RsaCtfTool` `4ffadb0…` — идеи атак: `dp_leak`, `smallq`,
  `cube_root`, `nonRSA`.
- `Ciphey/Ciphey` `c500baf…` — список декодеров: ROT47, base36/58/62/91,
  octal, Unicode/MIME, NFKC-буквы.
- `JohnHammond/ctf-katana` `f69496d…` — чек-лист PNG-форензики (`pngcheck`,
  `pngcsum`, CRC).

Что добавлено:

- **RSA:** `auto` импортирует **PEM/DER** публичный и закрытый ключ
  (`Crypto.PublicKey.RSA`), принимает `--cipher` (число/hex/файл). Новые атаки:
  утечка `dp/dq` (`dp-leak` + авто), малый простой множитель `smallq`,
  `n = p^k` (perfect power), `e = 1`, прямой `d`, простое `n`.
  `small-e` теперь перебирает `c + k*n`, а не только точный корень.
- **enc:** ROT47, ROT18, восьмеричные коды (`103 124 106` и `\103`), NFKC
  (математические/полноширинные буквы), ascii85, MIME encoded-word,
  base58/62/91/base32hex/quoted-printable через `crypto/obscure.py`.
- **png_chunks:** проверка CRC каждого чанка, вывод IHDR (размер/глубина/цвет),
  предупреждение о незнакомых критичных чанках и обрезанном файле,
  `--fix fixed.png` — пересчитать CRC, хвост после IEND сохраняется.
- Тесты: +15 проверок (RSA dp/smallq/p^k/e=1/PEM, enc rot47/nfkc/octal/ascii85/
  rot18/mime, png CRC/fix).

## 2026-11-08 — 0.35

- **DNS-каналы:** `network/dns_tunnel.py` понимает структурный канал
  `<session>.<index>.<hex>.<домен>`: сортирует куски по индексу, выкидывает
  ретрансмиты, собирает байты (включая короткий хвост последнего куска).
  Сам ищет `SEED`/`HOST`/`KEY`/`SALT`/`TOKEN` в мелких артефактах рядом с pcap
  (environ, cmdline, конфиги) и пробует производные ключи `sha256(seed[:@host])`,
  затем XOR → zlib/gzip/bz2/lzma. Новые флаги: `--seed`, `--host`, `--xor-key`,
  `--no-auto-keys`, `--out`. Проверено на реальном DFIR-наборе: флаг находится
  без ручной сборки.
- **Флаги:** в `flags.json` добавлены наборы `default` (ctf/flag/nto/innopolis/
  innoctf/vosh), `extended` и `russian` (NTO, InnoCTF, Innopolis, VOSH, VK Cup,
  Tinkoff и др.). Все префиксы и имя набора (`--flag-set`) — **без учёта
  регистра**: `NTO{}`, `nTo{}`, `InnoCTF{}`, `VOSH{}` ловятся одинаково.
- `toolbox.py auto/hint` для строки сначала проверяют, не является ли она уже
  флагом (раньше показывали только декодирования).
- `crypto/xor_known.py` сам пробует регистр known-текста (`ctf{` → `CTF{`),
  поэтому `solve` снова обходится одним шагом `xorknown` и не вытесняет
  `autocrack` из бюджета подшагов.
- **32 файловых скрипта** больше не падают трейсбеком на отсутствующий/
  нечитаемый файл: единый guard в `__main__` печатает `[-] не могу открыть: ...`
  (sweep: было 30 трейсбеков, стало 0; плюс `triage` и `rsa auto`).

## 2026-11-08 — 0.34

- **Ghidra 12.2** установлена в `F:\dev\ghidra_12.2_PUBLIC`, к ней **JDK 25**
  (`F:\dev\jdk-25.0.5+8`; Ghidra 12.x требует 25+, Java 17 не подходит).
- `reverse/ghidra_decomp.py` — headless-декомпиляция в C-текст
  (`toolbox.py ghidra bin --out dump.c`), сам находит Ghidra и JDK, чистит шум
  GhidraScript; постскрипт `reverse/ghidra_scripts/DumpDecomp.java`.
- `reverse/GHIDRA.md` — гайд: установка, запуск, импорт, хоткеи, crackme за
  10 минут, патчинг, headless, типовые ошибки.
- `solve`: для бинарников в `--deep` вызывается Ghidra; для PCAP — если рядом
  лежит лог, `mc --log` берёт секрет из него (Minecraft-класс задач).
- `disasm` (capstone) — шаг для ELF/PE в обычном режиме.

## 2026-11-08 — 0.33

- Новый `reverse/disasm.py` на capstone: ELF/PE, x86/x64/arm64, `.text` по
  секциям, `--interesting`, `--grep`, `--around`, `--strings` (RIP-relative
  ссылки → реальные строки), `--all`, `--limit`. Без Ghidra и без запуска.
- `solve` для ELF/PE добавляет шаг `disasm --interesting`.
- Установлен `capstone` 5.0.7.

## 2026-11-08 — 0.32

- GPU-кракинг заработал **без прав администратора**: из pip-колёс CUDA 12.9
  (`nvidia-cuda-runtime-cu12`, `nvidia-cuda-nvrtc-cu12` → `F:\dev\cuda-libs`)
  скопированы `nvrtc64_120_0.dll`, `nvrtc-builtins64_129.dll`, `cudart64_12.dll`
  в каталог hashcat. `hashcat -b -m 0` → **33.8 GH/s** на RTX 3070.
- Поставлен john 1.9.0-jumbo (CPU) как запасной движок.
- `hashcat_run.py`: `--engine auto|hashcat|john`, разбор potfile и `hash:pass`
  из вывода, понимает «All hashes found as potfile», печатает пароль в любом
  случае; при отсутствии устройств/библиотек сам уходит на john.

## 2026-11-08 — 0.31

- hashcat 8.0.0 установлен в `tools\hashcat-8.0.0`, кит находит его без PATH.
  `hashcat_run.py`: `--attack 0|1|3`, `--mask`, `--rules`, `--potfile`, автопоиск
  словаря (`F:\dev\wordlists\...`), реальный запуск и разбор potfile.
- Словари: `F:\dev\wordlists` (rockyou 133 МБ, john 15 МБ, xato 8 МБ, NCSC-100k,
  10k) + `_download.py` с проверенными URL.
- `solve`: для текста с хешами добавляет шаг `hashcat` (локальный словарь рядом
  с задачей или глобальный), если hashcat найден.

## 2026-11-08 — 0.30

- `hashcat_run.py` готов к GPU: `--attack 0|1|3`, `--mask`, `--rules`,
  `--potfile`; при установленном hashcat реально запускает и вытаскивает пароль
  из potfile, иначе печатает готовую команду и как поставить.
- GPU намеренно не тащим в Python: RTX 3070 оправдана только для hashcat-класса
  задач; XOR/LSB/кодировки — O(n), видюха только мешает.

## 2026-11-08 — 0.29

- `solve --jobs N` (по умолчанию 4): независимые шаги идут параллельно
  (ThreadPool + отдельные процессы), первый флаг останавливает остальные;
  папки разбираются файлами параллельно. Замер: 8 PNG в папке — 8.9 с при
  `--jobs 1` против 1.9 с при `--jobs 8` (8C/16T).

## 2026-11-08 — 0.28

- `rsa shared` понимает реальный JSON-реестр (`target`, `public_exponent`,
  `certificates[{id,n}]`, `wrapped_session_key`) и после расшифровки ключа сессии
  сам пробует поток `SHA256(key||nonce||counter) XOR` во всех порядках/эндианах
  (`wrapped_session_key` + `nonce` + `ciphertext` в том же файле) — одна команда
  на всю цепочку «общий множитель → ключ → поток».
- `solve` распознаёт такой JSON и ставит этот шаг первым.
- `gen_challenges.py`: шаблон `rsa_shared_stream` (реестр модулей + RSA-обёртка +
  поток) — проверено 1/1.

## 2026-11-08 — 0.27

- `solve`: DOCX-текст извлекается по `<w:t>` (один run на строку) и гоняется
  через `ws --mode trail` — ловятся хвостовые пробелы/табы, а не только zero-width.
- `rsa auto`: если n большой и слабостей не видно — явная подсказка про
  Coppersmith/решётки и Sage.
- `gen_challenges.py`: шаблон `docx_trail` (пробелы/табы в конце runs).

## 2026-11-08 — 0.26

- `solve`: распаковка GZIP и разбор содержимого; `hint.txt` рядом → ключ для
  ECB (`ecb --key K --decrypt`) и AES-CBC при наличии IV; `xorknown` теперь
  пробуется для любого блоба ≤64 КБ (раньше — только «непечатного»);
  после `carve` вложения прогоняются через `zipmeta`/`text`/`hunt` явно.
- `tests/gen_challenges.py`: RSA-«textbook» бывает решаемым — малая `e`
  (c=m³ без модуля) или близкие `p,q` (Ферма); добавлен шаблон `rsa_noise`
  (дамп с nonce/sha256/puzzle и настоящими n/e/c); DOCX — zero-width.
  XOR-подсказка: длина ключа 4 (иначе известного префикса не хватает —
  нерешаемая задача, а не баг кита).
- `enc.py`: для каждого декодированного варианта добавляется его реверс —
  цепочка «base64 → reverse» теперь распутывается за один запуск.
- `classical.py`: больше рестартов в `vigenere-crack` для коротких ключей.

## 2026-11-08 — 0.25

- `tests/gen_challenges.py` + `tests/fuzz_solve.py`: генератор мини-тасков и прогон
  по ним. Флаг придумывает человек, а кодирует/шифрует **программа** (кодировки,
  Цезарь, Виженер, XOR+подсказка, RSA textbook/p,q/с шумом, AES-ECB с ключом в
  hint, LSB PNG, комментарий ZIP, ZIP в ZIP, ZIP в томе, DNS в PCAP, zero-width DOCX).
  `solve` проверяется end-to-end, флаги в консоль решателя не попадают.
- `classical.py vigenere-crack`: сокращение периода ключа + старты по частотам —
  флаг в начале текста больше не сбивает поиск.
- `lsb.py --channel all`: если данные размазались, дополнительно пробует каждый
  канал по отдельности и показывает читаемый результат.
- `solve`: для DOCX извлекает `word/document.xml` и гоняет `ws` по нему; парсит
  `key/iv/mode` из соседних подсказок (`hint.txt`) и пробует AES/ECB.

## 2026-11-08 — 0.24

- `rsa auto`: из любого текста вытаскивает числа (метки `n/e/c/p/q`, hex, просто
  большие числа), угадывает роли и гоняет все атаки подряд — малая e (с перебором
  `c+k*n`), gcd между модулями, Ферма, p-1, rho, Винер, готовые p/q; печатает все
  расшифровки и флаги. Это «кинул файл с кучей чисел — получил результат».
- `solve --deep`: матрица вариантов по классам — LSB по каналам/порядку/битам,
  `runs`, глубокий autocrack/megarev, `reasm`/`mc` для PCAP, `ooxml`/`apk` для ZIP.
- `solve` для текста с ≥2 большими числами сразу зовёт `rsa auto`.

## 2026-11-08 — 0.23

- `enc.py`: починка «кракозябр» (`Ð¡Ð¾Ð¾Ð±Ñ‰…`): UTF-8-байты, показанные как
  cp1251/cp866/cp1252, восстанавливаются обратно в текст. Это кодировка, а не
  шифр — не надо XOR-ить. Кириллица теперь проходит фильтр печатности.
- `hint`: подсказывает про «кракозябры» в неопознанном тексте.

## 2026-11-08 — 0.22

- Новый режим `toolbox.py hint <цель>`: разбор с объяснением — что вижу, на что
  похоже, почему, что запустить и что смотреть, если не вышло. Учит классу
  задачи, а не подменяет решение.
- `solve` для текста: длинный текст без пробелов → `classical vigenere-crack`;
  ≥3 больших чисел → `all` (RSA/хеши).

## 2026-11-08 — 0.21

- `enc.py`: морзе текстом (`.... . .-.. .-.. ---`, `-`/`–`/`|`) и алфавит из двух
  символов без разделителей (`. -`, `AB`, `01`) → биты → ASCII. Закрывает кейсы,
  где «морзе» на деле двоичный код.
- `solve.py`: цепочка после основных шагов — из вывода инструментов вытаскиваются
  строки, похожие на ещё один слой кодировки, и прогоняются через `enc`.

## 2026-11-08 — 0.20

- Новый `web/recon.py` (`toolbox.py recon <url>`): заголовки, куки, JWT
  (header/payload), HTML-комментарии, формы и параметры, ссылки того же хоста,
  подозрительные строки и base64 в inline-JS, `robots.txt`/`sitemap.xml`, флаги.
- `auto` по папке: типы файлов, флаги по файлам, «что смотреть первым», план
  (`solve`/`flaghunt`/`triage`) вместо падения на каталоге.
- `solve` по папке: `hunt`/`flaghunt`, затем разбор до 12 самых интересных
  файлов по типам; URL — `recon` → `param` → (deep) `dirfuzz`; строки —
  `enc`/`autocrack`/`obscure`. Префиксы флагов прокидываются детям (`FLAG_PREFIXES`).
- `solve` не считает заглушки (`missing/placeholder/dummy/fake`) флагами и
  печатает «зацепки» (PIN, кандидаты в ключи), если флага в артефакте нет.

## 2026-11-08 — 0.19

- Новый `solve.py` (`toolbox.py solve <цель>`): автопилот по типу данных —
  архивы/картинки/звук/PCAP/ELF/PDF/SQLite/текст, рекурсия внутрь вырезанных
  файлов, XOR по префиксу флага, стоп на первом флаге, «зацепки» (PIN, ключи),
  если флага в артефакте нет. `--plan`, `--deep`, `--time`, `--log`, `--verbose`.
  Строки (`enc`/`autocrack`/`obscure`), URL (`param`), `host:port` — подсказки.

## 2026-11-08 — 0.18

- Новый `pwn/oracle.py`: универсальный TCP-цикл «вопрос → формула → ответ»
  для сервисов на N раундов. Regex вопроса, формула (`gcd`, `is_prime`, `pow`,
  `modinv`, …), шаблон ответа; `--peek`, `--until`, `--log`, `--repeat`.
  `--connect h:port`, группы regex доступны как `a`, `b`, `n1`, `nums`, `v`.
- `reverse/megarev.py`: эвристика «короткий числовой секрет рядом со словом
  PIN/key/code/pass/unlock» — PIN вроде `482917` находится без дизасма.
- `pwn/fmtstr.py scan`: `%1..%N$p` по сервису (`--connect`/`--local`), классификация
  указателей, ASCII, `--deref` с `%N$s`; находит флаг из окружения без своего скрипта.

## 2026-11-08 — 0.17

- `toolbox.py auto` переписан: реальный тип (а не расширение), вложенные
  сигнатуры с оффсетами, флаг внутри архива/документа, DNS-канал в PCAP,
  морзе/DTMF в WAV, защиты ELF/PE, теги текста; план — конкретные команды
  с причиной вместо фиксированной тройки. Ловит JSON-отказ API.
- `triage.py`: предупреждение «это ответ API, а не файл».
- `xor_known.py`: позиционный файл, длина ключа подбирается сама,
  печатает флаг через общий детектор.
- `megaall.py`, `megacrack.py`: файл можно дать позицией; known-plaintext XOR
  по префиксу флага (в т.ч. в `all`); внятное объяснение, каких материалов не хватает.
- `toolbox.py`: алиасы по имени файла (`megacrack`, `megaall`), подсказка
  «может, ты имел в виду» при опечатке.
- `dns_tunnel.py`: сам находит подозрительный домен (hex/base32/base64-метки),
  склеивает метки без ретрансмитов, декодирует и печатает флаг.
- `audio_tools.py`: надёжнее морзе (медианная оценка точки, глитчи), `--raw`
  с последовательностью `.-`, код в нижнем регистре, фильтр ложного DTMF,
  внятная ошибка на не-WAV.
- `param_probe.py`: SQLi-пейлоады `' OR 1=1--` и родня, поиск флагов в ответах.
- `common.py`: `printable_ratio` принимает str, `is_text` понимает кириллицу,
  `api_denial_note`, `xor_prefix_hits`.

## 2026-11-08 — 0.16

- Вывод не падает в pipe/файл: stdout/stderr переключаются на UTF-8 с
  `errors="replace"` во всех скриптах, `common.setup_stdio()`, `toolbox.py`
  отдаёт детям `PYTHONIOENCODING=utf-8`. Раньше `python toolbox.py index |
  Tee-Object log.txt` падал с `UnicodeEncodeError` на `→`/`—` в cp1251-консоли.
- Тест `unicode pipe (cp1251)`: index/triage/--help под cp1251 и pipe.

## 2026-11-07 — 0.15

- `MD_GUIDE.md`: навигатор по всем markdown-файлам (что где, зачем, когда читать).

## 2026-11-07 — 0.14

- `forensic/flag_hunt.py` и `linux/flag_hunt.sh`: флаги в `flag`, `flag.txt`,
  `flag_<random>`, `*flag*`, `user.txt`, `root.txt` + содержимое.
- `network/serve.py`: HTTP-раздача и приём файлов (upload + token).
- `linux/TRANSFER.md`: как залить скрипт на сервер и забрать файл.

## 2026-11-07 — 0.13

- Windows: `forensic/windows_triage.py` (hives/EVTX/Prefetch/LNK/строки).
- Git: `forensic/git_hunt.py` (история, объекты, удалённое, dangling, remotes).
- Браузеры: `forensic/browser_artifacts.py`.
- Office/PDF: `forensic/office_docs.py` (макросы, JS, embedded).
- Cloud: `forensic/cloud_creds.py` (+ metadata).
- Kubernetes: `linux/k8s_audit.sh`, `network/k8s_api.py`.
- Audio: `stego/audio_tools.py` (DTMF, морзе).
- Reverse: `reverse/lang_info.py` (.NET/Java/Go/Rust/Electron).
- Crypto: RSA `wiener` и `broadcast`.
- `linux/SSH.md`, `linux/LINUX.md`.

## 2026-11-07 — 0.12

- Docker: `forensic/docker_image.py` (слои, whiteouts, env/history, секреты, Dockerfile),
  `linux/docker_audit.sh`, `network/docker_api.py`, `linux/DOCKER.md`.

## 2026-11-07 — 0.11

- Аудит вывода: фильтры шума в `autocrack`, `megaall`, `megacrack`, `obscure auto`,
  `xor_scan` (`--min-score`, `--show-noise`).
- `WEB.md`: полный гид по веб-задачам, включая JS-консоль для новичков.

## 2026-11-07 — 0.10

- `reverse/megarev.py`: тип/защиты/упаковщики, энтропия, оверлей, строки,
  вложенные файлы, pyc-константы/дизассемблер, XOR-скан, ключи из строк и
  перебор шифров по блобам; поиск флагов в бинарном выводе.
- `doctext.py`, теги содержимого в `triage`, `GUIDE.md`.

## 2026-11-07 — 0.9

- `stego/whitespace.py`: интерпретатор Whitespace, space/tab-биты, zero-width,
  variation selectors, Unicode tags, braille, хвостовые пробелы.
- `stego/esolang.py`: Brainfuck, Ook!, Cow, Befunge-93, Deadfish, Whitespace.
- `crypto/obscure.py`: base58/62/91/85, uuencode, quoted-printable, punycode,
  A1Z26, Bacon, tap code, Polybius, keyboard shift, ADFGX/ADFGVX, Bifid,
  Porta, Beaufort, Gronsfeld, Autokey, Hill.

## 2026-11-07 — 0.8

- `megaall.py`: универсальный запуск «дай что есть» — артефакты, флаги, хеши,
  кандидаты в шифротекст, autocrack, ключи+megacrack, RSA (gcd/Ферма/малая e).
- `toolbox.py all`, INDEX, README, CHEATSHEET, EXAMPLES.

## 2026-11-07 — 0.7

- `crypto/megacrack.py`: шифротекст + материалы → токены, ключи (raw/hex/base64/
  md5/sha1/sha256, пары, xor) → XOR/RC4/AES-ECB/CBC/SHA256-поток/Виженер.
- `--deep`, лимиты токенов/пар и времени.

## 2026-11-07 — 0.6

- Настраиваемые форматы флагов: `FLAG_PREFIXES`, `FLAG_SET`, `FLAG_ANY`,
  `--flag-prefix`, `--flag-set`, `--any-prefix`, `flags.json`.
- Все инструменты с поиском флагов переведены на `common.find_flags`.
- Починена жадность regex: несколько флагов в одной строке больше не склеиваются.

## 2026-11-07 — 0.5

- `crypto/autocrack.py`: рекурсивные кодировки, Цезарь, аффинный, XOR (1 байт и
  повторяющийся), rail fence, ROT47, Виженер (coordinate ascent по триграммам),
  хеши с локальным словарём.
- `vigenere-crack` переписан: триграммы + coordinate ascent, устойчив на коротком тексте.
- `toolbox.py`: `autocrack` в реестре.
- Доки: INDEX, CHEATSHEET, EXAMPLES, crypto/README.

## 2026-11-07 — 0.4

- `toolbox.py`: единый диспетчер, `index`, `auto` (тип файла/строки + рекомендации).
- `common.py`: общие helpers (флаги, декодирование, sniff, strings).
- Новые инструменты:
  - reverse: `strings_filter`, `xor_scan`, `py_pack`;
  - pwn: `checksec`, `fmtstr`;
  - web: `jwt_brute`, `ssti_probe`, `dir_fuzz`;
  - network: `pcap_creds`;
  - stego: `audio_spectrum`, `qr_scan`;
  - forensic: `apk_info`;
  - crypto: `aes_ecb`, `hashcat_run`;
  - crypto: `vigenere-crack`, `rsa_tool fermat/batch`.
- `--json` у `triage`, `artifact_hunt`, `mc_decrypt`.
- `--max-packets` у `pcap_report`.
- `INDEX.md`, `QUICKSTART.md`.
- Тесты: 52 (было 35), temp-каталог удаляется автоматически.

## 2026-11-07 — 0.3

- `mc_decrypt`, `mc_blocks`, `bitmap_font`, `udp_payloads`.
- `rsa_tool`, `stream_sha256`, `otp_reuse`, `android_backup`, `png_chunks`.
- `dns_tunnel`, `pcap_http`, `param_probe`.
- `privesc.sh`, `gtfobins.py`, `script_audit.py`.
- `artifact_hunt`, `volatility_text`, `tcp_reassemble`.

## 2026-11-07 — 0.2

- Базовый набор: stego, forensic, network, crypto, web, pwn, misc.
- `triage`, `enc`, `jwt_tool`, `ret2win`, `timeconv`.
- `tests/selftest.py`.
