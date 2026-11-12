# MD_GUIDE — навигатор по всем markdown-файлам

Это карта документации: что за файл, зачем он, когда его открывать.
Если не знаешь, с чего начать — прочитай этот файл, дальше он приведёт куда надо.

---

## 0. Три файла, которые нужны чаще всего

| Ситуация | Файл |
|---|---|
| «Я тут первый раз / что вообще есть» | `README.md` |
| «Мне дали что-то, что с этим делать» | `GUIDE.md` |
| «Какая команда/инструмент для X» | `INDEX.md` + `CHEATSHEET.md` |

---

**PPC и интерактивные задачи:** `PPC.md` — таксономия, автономность, стенд 21/21.

**Быстрый вход для новичка:** `START.md` — «что видишь → какую команду», без теории.

## 1. Карта по назначению

### Старт и навигация

| Файл | Что внутри | Когда открывать |
|---|---|---|
| `README.md` | обзор кита, дерево папок, быстрый старт, зависимости, форматы флагов | первый запуск, «что вообще есть» |
| `MD_GUIDE.md` | этот навигатор | потерялся в документации |
| `INDEX.md` | все инструменты: имя, что делает, пример команды | «чем решить задачу X» |
| `GUIDE.md` | дерево решений «что мне дали → как проверить → чем работать» | дали файл/документ/архив/строку и непонятно, что это |
| `QUICKSTART.md` | 5 минут до первого результата | нужен быстрый старт без чтения всего |
| `CHANGELOG.md` | что и когда добавлялось | «а был ли раньше инструмент X» |

### Большие гайды по категориям

| Файл | Что внутри | Когда открывать |
|---|---|---|
| `WEB.md` | веб целиком: recon, DevTools, SQLi, XSS, SSRF, XXE, LFI, upload, SSTI, JWT, десериализация, prototype pollution, GraphQL/OAuth/SAML, JS-консоль для новичков | любая веб-задача |
| `linux/LINUX.md` | пост-эксплуатация: зашёл на машину → нашёл флаг → root (sudo, SUID, capabilities, cron, PATH, контейнер, k8s) | дали SSH/шелл/машину |
| `linux/DOCKER.md` | побег из контейнера: docker.sock, privileged, release_agent, core_pattern, nsenter, API, форензика образа | дан контейнер или `image.tar` |
| `linux/SSH.md` | подключение: `ssh`, ключи, `ProxyCommand` + `openssl s_client`, туннели, `ssh2john` | надо подключиться/пробросить порт |
| `linux/TRANSFER.md` | как залить скрипт на сервер и забрать файл: HTTP, curl/wget/python, base64, nc, scp, docker/kubectl cp | есть шелл, но нет файлов на цели |
| `MANUAL.md` | ручная работа: чтение условия (и `solve --desc`), OSINT, web, crypto, reverse, network, forensic, pwn, тайминг, журнал; §14 — схема `solve --json`/`--events` | не хватает «как думать», а не команды; интеграция solve с сайтом/агентом |

### Справочники

| Файл | Что внутри | Когда открывать |
|---|---|---|
| `CHEATSHEET.md` | команды по категориям: файлы, стего, forensic, network, crypto, web, pwn, linux, флаги | «напомни команду» |
| `EXAMPLES.md` | 64 рецепта типовых задач (от welcome до Docker/K8s) | «а как обычно решают такое» |
| `web/web_checklist.md` | короткий чек-лист по вебу (IDOR, SQLi, LFI, JWT, SSTI, upload, логика) | нужен быстрый чек-лист, а не весь WEB.md |
| `pwn/pwn_notes.md` | pwn: ret2win, format string, SUID, eval, оффсеты | pwn-задача |
| `reverse/GHIDRA.md` | Ghidra: установка, GUI, хоткеи, crackme за 10 минут, headless | реверс бинарника, нужен декомпилятор |

### README по папкам (список инструментов)

| Файл | Когда открывать |
|---|---|
| `stego/README.md` | стего: LSB, PNG-чанки, аудио, QR, глифы |
| `forensic/README.md` | форензика: архив, диск, Windows, git, браузер, Docker, APK |
| `network/README.md` | сеть: PCAP, TCP, Minecraft, UDP, DNS, HTTP, creds, Docker/K8s API |
| `crypto/README.md` | крипта: классика, RSA, XOR, потоки, hashes, autocrack/megacrack |
| `linux/README.md` | Linux: privesc, GTFObins, Docker, K8s, SSH, transfer |
| `web/README.md` | веб: JWT, SSTI, param, dirfuzz |
| `pwn/README.md` | pwn: checksec, ret2win, fmtstr |
| `reverse/README.md` | реверс: strings, XOR, упаковщики, megarev, lang |

---

## 2. «У меня ситуация X — что открыть»

| Ситуация | Открывай |
|---|---|
| Дали файл, не знаю тип | `GUIDE.md` → `toolbox.py auto` |
| Дали DOCX/PDF, внутри пусто/невидимое | `GUIDE.md` + `linux/LINUX.md` → `toolbox.py text` → `ws` |
| Дали строку/кодировку | `CHEATSHEET.md` (Crypto) или `GUIDE.md` |
| Дали архив/дамп | `GUIDE.md`, `forensic/README.md` |
| Дали PCAP | `network/README.md`, `CHEATSHEET.md` (Network) |
| Дали бинарник | `reverse/README.md`, `pwn/pwn_notes.md`, `EXAMPLES.md` (Reverse/PWN); запуск — `linux/wsl.py run .\bin --dir` |
| Дали сайт | `WEB.md` (полный), `web/web_checklist.md` (быстрый) |
| Дали SSH/шелл | `linux/LINUX.md`, `linux/flag_hunt.sh`, `linux/TRANSFER.md` |
| Дали контейнер | `linux/DOCKER.md`, `linux/docker_audit.sh` |
| Дали под Kubernetes | `linux/LINUX.md` (раздел 9), `network/k8s_api.py` |
| Нужно залить скрипт/забрать файл | `linux/TRANSFER.md` |
| Не работает SSH/нужен туннель | `linux/SSH.md` |
| Не понимаю, как решать руками | `MANUAL.md` |
| Забыл команду | `CHEATSHEET.md` |
| Нужен пример задачи | `EXAMPLES.md` |
| Ищу инструмент по названию | `INDEX.md` или `python toolbox.py index` |

---

## 3. Как читать документацию (порядок)

1. **`README.md`** — 5 минут, понять структуру.
2. **`GUIDE.md`** — когда реально дали задачу.
3. Дальше — категорийный гайд (`WEB.md`, `linux/LINUX.md`, `linux/DOCKER.md`…).
4. **`CHEATSHEET.md`** — команды под рукой.
5. **`EXAMPLES.md`** — если задача похожа на типовую.
6. **`MANUAL.md`** — если хочется научиться, а не подсмотреть.

---

## 4. Чем эти файлы отличаются

- `GUIDE.md` — **что дали** и куда бежать.
- `MANUAL.md` — **как думать** и что делать руками.
- `CHEATSHEET.md` — **какие команды**.
- `EXAMPLES.md` — **как обычно выглядит задача** и рецепт.
- `INDEX.md` — **какие есть инструменты**.
- `README.md` — **что это за кит**.
- `MD_GUIDE.md` — **что читать**.

---

## 5. Если файл не открывается

Все пути — относительно `C:\Users\nispa\.vscode\projectPy\toolbox`.
Открыть можно любым редактором или:

```bash
python -c "import webbrowser; webbrowser.open(r'C:\Users\nispa\.vscode\projectPy\toolbox\WEB.md')"
```

Или просто `notepad WEB.md`.
