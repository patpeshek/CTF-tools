# START — что делать прямо сейчас

Одна страница без теории. Если совсем не понимаешь, что перед тобой:

```powershell
python toolbox.py solve <файл|папка|строка|URL|host:port> --deep
```

`solve` сам определит тип, прогонит подходящие шаги и остановится, когда
найдёт флаг. Всё остальное ниже — на случай, если хочется быстрее и точнее.

---

## Что видишь → какую команду

| Что видишь | Команда |
|---|---|
| **Крипто: непонятный файл/строка** | `python toolbox.py solve cipher.bin --deep` |
| Крипто: только понять, что это | `python toolbox.py auto cipher.bin` |
| XOR, известен формат флага | `python toolbox.py xorknown cipher.bin --known "CTF{"` |
| Строка в несколько слоёв (base64→hex→ROT13→XOR…) | `python toolbox.py chain "<строка>"` (`solve` зовёт его сам) |
| RSA (`n,e,c`, PEM, «утечка») | `python toolbox.py rsa auto key.pem --cipher c.txt` |
| AES-файл, ключ где-то рядом | `python toolbox.py aes secret.enc --auto --from-bin encryptor` |
| Классика: Цезарь/Виженер/замена | `python toolbox.py classical "текст"` |
| Хеш, надо подобрать | `python toolbox.py hashcat <hash> --wordlist F:\dev\wordlists\rockyou.txt` |
| **Стего: картинка** | `python toolbox.py auto pic.png` |
| LSB в PNG | `python toolbox.py lsb pic.png --channel all` |
| Хвост после JPEG/PNG | `python toolbox.py jpeg_tail pic.jpg --extract out` |
| Звук (морзе/DTMF/спектр) | `python toolbox.py audiotools sound.wav --raw` |
| Текст на картинке/кадре (OCR) | `python toolbox.py ocr pic.png --variants` |
| Видео/GIF: кадры и текст | `python toolbox.py video clip.mp4 --every 5` |
| 100000 строк, одна отличается | `python toolbox.py nearlines file.txt` |
| Скрытый текст/пробелы/DOCX | `python toolbox.py ws file.txt` / `python toolbox.py doctext file.docx` |
| **Форензика: образ/архив** | `python toolbox.py solve disk.img --deep` |
| ZIP внутри файла/тома | `python toolbox.py carve fragment.bin --out carved` |
| `.xz`/`.bz2`/`.tar` внутри | `solve` распаковывает сам; вручную — `python toolbox.py auto file.xz` |
| Метаданные | `python toolbox.py exif file.jpg` |
| ZIP-комментарии/пароли | `python toolbox.py zipmeta file.zip` |
| **Сеть: pcap** | `python toolbox.py dns capture.pcap` |
| Что вообще в трафике | `python toolbox.py pcap capture.pcap` |
| HTTP-объекты / креды | `python toolbox.py http capture.pcap` / `python toolbox.py creds capture.pcap` |
| **Веб: сайт** | `python toolbox.py recon http://host/` |
| SQLi/параметры | `python toolbox.py param "http://host/?q=1"` |
| JWT | `python toolbox.py jwt auto "$TOKEN" --wordlist words.txt` |
| Директории | `python toolbox.py dirfuzz http://host/ -w words.txt` |
| **PWN: бинарь + сервис** | `python toolbox.py checksec ./bin` |
| Format string | `python toolbox.py fmtstr auto --connect host:port` |
| Переполнение/ret2win | `python toolbox.py ret2win payload --offset 72 --addr 0x4011a2` |
| **Reverse: бинарь** | `python toolbox.py megarev ./bin` |
| Декомпиляция в C | `python toolbox.py ghidra ./bin` |
| Дизасм/строки | `python toolbox.py disasm ./bin --strings` |
| **PPC / интерактивный сервис** | `python toolbox.py game --connect host:port --auto` |
| Сервис «ответь N раундов» | `python toolbox.py oracle --connect host:port --auto` |
| Wordle/«5 букв» | `python toolbox.py wordle play --connect host:port` |
| **OSINT: фото** | `python toolbox.py exif photo.jpg` (дальше — ссылки/поиск) |
| **ELF под Linux** | `python linux/wsl.py run .\chall --dir` |

---

## Три команды, которые надо помнить

```powershell
python toolbox.py auto  <цель>          # что это вообще и что делать
python toolbox.py solve <цель> --deep   # автопилот: прогнать всё до флага
python toolbox.py hint  <цель>          # объяснить, почему такой план
```

`solve` принимает файл, папку, строку, URL и `host:port`.

---

## Если сервис «живой» и что-то рисует

```powershell
python toolbox.py game --connect host:port --auto
```

Он сам понимает: вопрос с числами, Wordle, «нажми клавишу», угадайка
(бинарный поиск) или поле. Флаг забирает из любого места ответа.

Если протокол совсем незнакомый:

```powershell
python toolbox.py game --connect host:port --record game.log   # записать
python toolbox.py game --connect host:port --auto --explore    # какие клавиши реагируют
```

Дальше — плагин `plugins/имя.py` с функцией `move(text, state)`; шаблон
лежит в `plugins/_template.py`, API — в `plugins/README.md`.

---

## Флаги

По умолчанию ловятся `ctf/flag/nto/innopolis/innoctf/vosh`. Если префикс
другой:

```powershell
python toolbox.py solve file.bin --flag-prefix "supersecret"
python toolbox.py solve file.bin --flag-set russian
python toolbox.py solve file.bin --any-prefix
```

---

## Несколько PPC сразу

На каждый сервис — **свой процесс**, но инструмент один и тот же. Писать
отдельный скрипт под каждый тип не нужно.

| Что за сервис | Команда |
|---|---|
| Чистый Q&A: «ответь N раундов», числа/слова | `python toolbox.py oracle --connect host:port --auto` |
| Экран, игры, клавиши, Wordle, угадайка, поле | `python toolbox.py game --connect host:port --auto` |
| Не уверен, что это | `python toolbox.py game --connect host:port --auto` (сам сведётся к Q&A) |

Запускать можно параллельно: каждому сервису — своё окно/порт. Полезно писать
транскрипт, чтобы потом понять, где застрял:

```powershell
python toolbox.py oracle --connect h1:p1 --auto --dump q1.txt
python toolbox.py game   --connect h2:p2 --auto --record g2.log
```

Если сервис незнакомый и `auto` встал:

```powershell
python toolbox.py game --connect h:p --auto --explore    # какие клавиши реагируют
python toolbox.py game --connect h:p --record game.log   # записать протокол
```

Дальше — `plugins/имя.py` с `move(text, state)`. Один раз написал под этот
протокол — дальше он подхватывается сам по баннеру.

---

## Если ничего не сработало

1. `python toolbox.py auto <цель>` — посмотреть реальный тип и план.
2. `python toolbox.py hint <цель>` — объяснение словами.
3. `python toolbox.py solve <цель> --deep --time 120` — дать больше времени.
4. Посмотреть `INDEX.md` (все инструменты) и `GUIDE.md` (как выбирать).
