# Шпаргалка по командам (Kali/Linux + Windows)

## Первый прогон по любому файлу

```bash
file f; strings -a f | head -100; exiftool f
xxd f | head; xxd f | tail
binwalk f; foremost -i f -o out
unzip -l f; 7z l f; zipinfo -z f      # -z — комментарии архива
```

## Стего

```bash
zsteg -a pic.png                 # PNG LSB
steghide extract -sf pic.jpg     # пароль может быть в тексте задачи
stegsolve                        # GUI: каналы, биты, frame browser
binwalk --dd='.*' pic.jpg        # вырезать всё
python stego/lsb.py pic.png --channel r --bits 2
python stego/alpha.py pic.png --channel a
python stego/jpeg_tail.py pic.jpg --extract out
```

Онлайн (если есть доступ): aperisolve.com, 29a.ch/photo-forensics, stegonline.

## Forensic

```bash
python forensic/zipmeta.py a.zip --decode
python forensic/ipa_info.py app.ipa --out app      # iOS: Info.plist, строки
python forensic/geo_photo.py photo.jpg --json r.json  # EXIF/GPS + ссылки
sudo bash forensic/disk_triage.sh disk.img
photorec disk.img                 # восстановление удалённых
testdisk disk.img                 # разделы
cryptsetup luksOpen disk.img secure && mount /dev/mapper/secure /mnt
```

## Network

```bash
python network/pcap_report.py cap.pcap --dump streams
python network/icmp_payloads.py cap.pcap            # ICMP payload/каналы
tshark -r cap.pcap -q -z io,phs            # иерархия протоколов
tshark -r cap.pcap -Y http.request -T fields -e http.host -e http.request.uri
tshark -r cap.pcap -T fields -e data.text -Y "data.text" | tr -d '\n'
strings cap.pcap | grep -iE 'flag|ctf|pass'
```

В Wireshark: Statistics → Protocol Hierarchy / Conversations; Follow → TCP/HTTP Stream;
File → Export Objects → HTTP.

## Crypto

```bash
python crypto/classical.py caesar --text "..."
python crypto/classical.py affine --text "..." --known "AGENT"
python crypto/classical.py vigenere --text "..." --key LEMON
python crypto/classical.py multitap --text "222 33 555"
python crypto/genetic.py "UGUACUUUC{...}"
python crypto/xor_known.py enc.bin --known "CTF{"          # ключ и длину найдёт сам
python crypto/aes_file.py enc.bin --key STR --key-xor 42 --keylen 32 --iv IVSTR
python crypto/aes_file.py enc.bin --auto --from-bin encryptor   # ключ/IV из строк бинарника
python crypto/hash_id.py 5f4dcc3b5aa765d61d8327deb882cf99
python enc.py "Q1RGe2ZsYWd9"                              # все базовые декоды
python enc.py --file utf16.txt                            # utf-16/32, cp1251, base36/58/85/z85...
python toolbox.py solve file                              # enc уже включён в автопилот
```

Внешние: dcode.fr (все классические шифры), CyberChef (цепочки преобразований),
hashcat (`-m 0` md5, `-m 1000` ntlm, `-m 1400` sha256, `-m 10900` pbkdf2-sha256),
john (`ssh2john`, `zip2john`, `rar2john`).

```bash
hashcat -m 0 -a 0 hash.txt rockyou.txt
john --wordlist=rockyou.txt hash.txt
```

## Web

```bash
gobuster dir -u http://host -w /usr/share/wordlists/dirb/common.txt
ffuf -u http://host/FUZZ -w wordlist.txt
sqlmap -u 'http://host/?id=1' --batch --dbs
python web/jwt_tool.py forge --secret KEY --sub admin --role admin
python web/jwt_tool.py auto "$TOKEN" --wordlist words.txt   # alg:none + подбор секрета
python web/param_probe.py "http://host/?q=0"                # SQLi-пейлоады + флаги в ответе
python web/recon.py "http://host/"                          # заголовки/куки/JWT/JS/robots
```

Чек-лист: `web/web_checklist.md`.

## PWN

```bash
checksec --file=./bin
objdump -d ./bin | grep -A30 '<main>'
python pwn/ret2win.py pattern 200
python pwn/ret2win.py offset 0x6161616b
python pwn/ret2win.py payload --offset 80 --addr 0x4011a2 --remote 1.2.3.4:9001
```

gdb: `cyclic 200`, `cyclic -l 0x6161616b`, `x/20gx $rsp`.

## OSINT

- Обратный поиск картинки: Яндекс.Картинки, Google Lens, TinEye, Bing Visual Search.
- Метаданные: `exiftool`, `python forensic/exif.py`.
- Время: `python misc/timeconv.py --ts ...`; сопоставить с расписанием/событием.

# интерактивные задачи (не только ppc)
python misc/game_bot.py --connect h:p --auto          # вопрос/слово/клавиши/поле
python misc/game_bot.py --connect h:p --record game.log  # записать протокол
python misc/game_bot.py --connect h:p --plugins-dir plugins --list-plugins
python misc/game_bot.py --connect h:p --keys q --stamina 25  # гонка
python misc/wordle_bot.py play --connect h:p --words F:\dev\wordlists\russian5.txt
python misc/game_bot.py --connect h:p --auto --explore   # какие клавиши реагируют
python misc/formats.py --list                        # кэш разметок
python toolbox.py ppc "12 ? 5 = 17"                     # что движок понял
python tests/ppc_bench.py --only arith,captcha       # локальный стенд PPC
python misc/formats.py --set "ГЖС" --green Г --yellow Ж --gray С
python misc/ocr.py pic.png --variants                  # текст с картинки
python misc/video.py clip.mp4 --every 5                # кадры + OCR
python misc/nearlines.py file.txt                      # 100000 почти одинаковых строк
python tests/corpus_bench.py --category crypto         # прогон по реальным задачам
- Геолокация: подписи, вывески, архитектура, растительность, тени (SunCalc).
- Никнеймы: поиск по username, архивы (Wayback Machine).

## RSA и самодельные шифры

```bash
python crypto/rsa_tool.py shared --moduli moduli.txt --target name --e 65537 --cipher 0x...
python crypto/rsa_tool.py shared --json registry.json --target name --cipher-field wrapped
python crypto/rsa_tool.py common-modulus --n ... --e1 3 --c1 ... --e2 65537 --c2 ...
python crypto/rsa_tool.py small-e --n ... --e 3 --c ...
python crypto/rsa_tool.py factor --n ... --p ...

python crypto/stream_sha256.py --cipher <hex> --key <...> --nonce <...>
python crypto/stream_sha256.py --cipher <hex> --key <...> --nonce <...> --brute
python crypto/otp_reuse.py --c1 <hex> --c2 <hex> --crib "the "
python crypto/classical.py vigenere-crack --text "<шифротекст>"
python crypto/rsa_tool.py fermat --n <n> --e 65537 --cipher <c>
python crypto/rsa_tool.py batch --moduli moduli.txt
python crypto/rsa_tool.py dp-leak --n ... --e 65537 --dp <d mod p-1> --cipher ...
python crypto/rsa_tool.py auto public.pem --cipher cipher.bin
python crypto/rsa_tool.py auto task.txt          # n/e/c, dp, d, p,q — что найдёт
python crypto/autocrack.py --text "..."
python crypto/autocrack.py --hex ... --deep
python crypto/autocrack.py --hash <hash> --wordlist auto
python crypto/megacrack.py --cipher-file enc.bin --material note.txt
python crypto/megacrack.py --cipher-file enc.bin --material-dir dump --deep
python megaall.py --dir dump --deep
python megaall.py --file enc.bin --file note.txt
```

## Протоколы и кастомные форматы

```bash
python network/tcp_reassemble.py cap.pcap --dump streams
python network/mc_decrypt.py cap.pcap --log latest.log --dump packets.jsonl
python network/mc_blocks.py cap.pcap --log latest.log --csv board.csv
python stego/bitmap_font.py board.csv --ascii --flip-y --decode --lower
python network/udp_payloads.py cap.pcap --sep / --signature MOBILE/
python network/dns_tunnel.py cap.pcap            # домен канала определяется сам
python network/pcap_http.py cap.pcap --out objects
python stego/png_chunks.py pic.png --extract chunks
python blockchain/evm_decode.py 0xa9059cbb...          # EVM calldata
python blockchain/evm_decode.py --sig "transfer(address,uint256)"
python ai/pickle_scan.py model.pkl                     # опасные глобалы, без запуска
```

## Linux: разведка и privesc

```bash
bash linux/privesc.sh | tee privesc.txt
python linux/gtfobins.py --check "find,base64,vim,tar"
python linux/gtfobins.py --from-sudo sudo.txt
python linux/script_audit.py /usr/local/sbin/reconcile --check-writable
```

## Артефакты и текстовые выгрузки

```bash
python forensic/artifact_hunt.py dump --zip --context 1
python forensic/android_backup.py dump --json android.json
python forensic/volatility_text.py windows.envars.txt --name agent
python forensic/volatility_text.py windows.pstree.txt --grep lab --keys
```

## Быстрые команды

```bash
# единая точка входа
python toolbox.py auto <файл|строка>
python toolbox.py solve <файл>              # прогнать всё самому до флага
python toolbox.py solve <файл> --deep --time 180
python toolbox.py solve <файл> --desc "текст условия"    # подсказки/формат флага/пароли → план
python toolbox.py solve --desc-file task.txt            # цель (URL, host:port) — из условия
python toolbox.py hint <файл>               # объяснить, что это и почему
python toolbox.py index

# тесты
python tests/selftest.py
python tests/gen_challenges.py --out F:\AIproject\_scratch\gentasks --seed 1
python tests/fuzz_solve.py --dir F:\AIproject\_scratch\gentasks --time 45

# binary
python pwn/checksec.py ./bin
python pwn/fmtstr.py find --count 40
python pwn/fmtstr.py scan --connect h:1337 --deref    # %N$p -> индексы -> %N$s
python pwn/fmtstr.py auto --connect h:1337          # перебрать %1..%40$s, искать флаг
python pwn/oracle.py --connect h:1337 --peek          # что вообще спрашивает сервис
python pwn/oracle.py --connect h:1337 --preset coprime   # YES/NO: взаимно простые
python pwn/oracle.py --connect h:1337 --auto             # сам угадывает класс и стратегию
python pwn/oracle.py --connect h:1337 --auto --promote 10 --dump q.txt
python pwn/oracle.py --connect h:1337 --preset prime     # YES/NO: простое
python pwn/oracle.py --connect h:1337 --preset calc      # посчитать a+b
python pwn/oracle.py --connect h:1337 --preset vowels    # гласные/согласные
python pwn/oracle.py --connect h:1337 --match "(\d+) +(\d+)" --expr "gcd(a,b)==1" --send-expr "'YES' if v else 'NO'"
python pwn/oracle.py --local "python srv.py" --match "(\d+)" --expr "v*2"   # локальный процесс
python reverse/strings_filter.py ./bin --grep "flag|key|pass"
python reverse/xor_scan.py ./bin --keylen 8
python reverse/py_pack.py ./app.exe
python reverse/megarev.py --file ./bin --deep

# web
python web/jwt_brute.py "<token>" --wordlist words.txt
python web/ssti_probe.py "http://host/?q=1"
python web/dir_fuzz.py http://host --ext php

# network
python network/pcap_creds.py cap.pcap
python network/pcap_report.py cap.pcap --max-packets 5000

# wsl: свой Linux (Arch) для запуска ELF
wsl -d archlinux                                   # шелл, юзер ctf / пароль ctf
python linux/wsl.py info
python linux/wsl.py run .\chall --dir              # копирует в ~/inbox, +x, запускает
python linux/wsl.py run .\chall --arch aarch64     # aarch64 через qemu (нужен sysroot)
python linux/wsl.py inbox                          # что уже перенесено
python linux/wsl.py sh "checksec --file=~/inbox/chall"
ffuf -u http://host/FUZZ -w ~/wordlists/rockyou.txt   # ffuf 2.3.0, словари с F:
ffuf -u http://host/api/FUZZ -w words.txt -mc 200,301 -fs 0
paru -Syu                                          # обновить репы + AUR

# stego
python stego/audio_spectrum.py sound.wav --peaks
python stego/carve.py blob.bin --out carved        # ZIP ищется по EOCD и распаковывается
python stego/qr_scan.py pic.png
python stego/whitespace.py file.txt
python stego/esolang.py file.bf
python crypto/obscure.py auto --text "..."

# forensic
python forensic/apk_info.py app.apk
python forensic/docker_image.py image.tar --out fs
bash linux/docker_audit.sh
bash linux/k8s_audit.sh
python network/docker_api.py --host http://ip:2375 --list
python network/k8s_api.py --host https://ip:6443 --token T --list
python forensic/git_hunt.py repo --all-objects
python forensic/browser_artifacts.py "Chrome/User Data"
python forensic/windows_triage.py dump
python forensic/office_docs.py doc.docx --out out
python forensic/cloud_creds.py dump --metadata
python stego/audio_tools.py sound.wav --raw     # морзе/DTMF + проверка .-
python reverse/lang_info.py app.exe
python crypto/rsa_tool.py wiener --n ... --e ... --cipher ...
python crypto/rsa_tool.py broadcast --e 3 --pairs "n:c" --pairs "n:c" --pairs "n:c"
python forensic/flag_hunt.py dump
bash linux/flag_hunt.sh
python network/serve.py --dir . --port 8000 --upload --token s3cr3t

# crypto
python crypto/aes_ecb.py cipher.bin
python crypto/hashcat_run.py <hash> --dry-run
```

## Флаги

По умолчанию: `ctf`, `flag`, `nto`, `innopolis`, `innoctf`, `vosh` — регистр
не важен (`NTO{}`, `nTo{}`, `VOSH{}` ловятся одинаково).

```bash
$env:FLAG_PREFIXES="ACME,CTF"      # PowerShell: для всех инструментов
python triage.py dump --flag-prefix ACME
python triage.py dump --flag-set RUSSIAN   # NTO/InnoCTF/Innopolis/VOSH/...
python forensic/artifact_hunt.py dump --flag-prefix ACME
python crypto/autocrack.py --text ... --flag-prefix ACME
python toolbox.py auto file --flag-prefix ACME
python triage.py dump --flag-set extended
python triage.py dump --any-prefix
```

## Порядок работы

- Сначала просмотри все задачи и отметь, что понятно с первого взгляда.
- Бери то, что решается быстро, независимо от категории.
- Два разных подхода не сработали — переключись.
- Перед отправкой проверь формат ответа (регистр, обёртка, пробелы).
