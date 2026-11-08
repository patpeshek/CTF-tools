# LINUX — зачем этот раздел и что делать после входа на машину

Коротко: **`linux/` — это про этап «мне уже дали шелл на Linux-машине/контейнере,
что дальше?»**. Не про то, как подключиться (это `ssh`/`SSH.md`), и не про веб/крипту.

В CTF это задачи вида:

- дали `ssh player@host` и пароль `player` — надо найти `user.txt` и `root.txt`;
- дали reverse shell от веб-приложения — надо повысить права до root;
- дали контейнер — надо из него вылезти на хост;
- дали pod Kubernetes — надо достать секреты.

Во всех случаях ты уже **внутри**, но с низкими правами. Раздел помогает:
1. понять, что за система и какие права;
2. найти, где флаг;
3. повысить права до root (или вылезти из контейнера);
4. не забыть про SSH-туннели/ключи.

---

## 0. Что лежит в `linux/`

| Файл | Для чего |
|---|---|
| `privesc.sh` | разведка: `sudo -l`, SUID, capabilities, cron, записываемые файлы, группы, docker.sock |
| `flag_hunt.sh` | поиск `flag`, `flag.txt`, `flag_<random>`, `*flag*`, `CTF{...}` |
| `gtfobins.py` | оффлайн-таблица «как выйти в root через штатный бинарь» |
| `script_audit.py` | анализ root-скрипта: что `source`-ит и можно ли подменить файл |
| `docker_audit.sh` | аудит контейнера: capabilities, сокет, монтирования, cgroup, host PID |
| `k8s_audit.sh` | аудит пода Kubernetes: service account, API, secrets |
| `wsl.py` | запуск ELF с Windows в WSL-дистрибутиве Arch: копирует файл, ставит `+x`, запускает (gdb, pwntools, qemu) |
| `DOCKER.md` | побег из контейнера, форензика образа |
| `SSH.md` | подключение, ProxyCommand/openssl s_client, туннели, ключи |
| `TRANSFER.md` | как залить скрипт на сервер и забрать файлы |
| `LINUX.md` | этот файл |

---

## 1. Первые 5 минут на машине

```bash
id
uname -a
cat /etc/os-release
sudo -l
groups
ls -la ~
cat ~/.bash_history
```

Затем:

```bash
bash linux/privesc.sh | tee privesc.txt
```

Скрипт сам соберёт: SUID/SGID, capabilities, cron, записываемые конфиги,
docker.sock, PATH, процессы root, свежие файлы.

---

## 2. Где обычно флаг

- `/root/flag`, `/root/root.txt`, `/home/*/user.txt`;
- `/flag`, `/flag.txt`, `/opt/flag`, `/srv/flag`;
- в БД (`sqlite3`, `mysql`), в env, в `/run/secrets`;
- в конфиге приложения, в логах, в `.bash_history`;
- в Docker-образе (слои/whiteouts) — `forensic/docker_image.py`.

Быстрый поиск:

```bash
bash linux/flag_hunt.sh
find / -type f \( -iname '*flag*' -o -iname 'user.txt' -o -iname 'root.txt' \) 2>/dev/null
grep -Ril 'CTF{' / 2>/dev/null | head
```

---

## 3. sudo

```bash
sudo -l
```

Варианты:

- `(ALL) NOPASSWD: /usr/bin/find` → GTFObins:
  ```bash
  sudo find . -exec /bin/sh \; -quit
  ```
- `NOPASSWD: /usr/bin/base64`, `less`, `vim`, `tar`, `python3`, `mysql` — см. `gtfobins.py`.
- `SETENV` → `sudo LD_PRELOAD=./pe.so /opt/script.sh`.
- `sudo bash script.sh` → подменить скрипт/переменную, которую он читает.
- `sudo mysql` → `\! id` внутри.

```bash
python linux/gtfobins.py --check "find,base64,vim,tar"
python linux/gtfobins.py --from-sudo sudo.txt
```

---

## 4. SUID / SGID

```bash
find / -perm -4000 -type f 2>/dev/null
find / -perm -2000 -type f 2>/dev/null
```

Дальше:

- стандартный бинарь (`find`, `vim`, `base64`, `cp`) → GTFObins;
- кастомный бинарь → `strings`, Ghidra, проверить, что он читает/запускает;
- SUID-читалка файла → path traversal к `/root/flag`;
- SUID + shared library → `LD_PRELOAD` (если разрешено).

---

## 5. Capabilities

```bash
getcap -r / 2>/dev/null
capsh --print
```

Опасно:

- `cap_setuid+ep` → можно стать root;
- `cap_sys_admin` → монтирование, cgroup/core_pattern;
- `cap_dac_read_search` → читать любые файлы;
- `cap_sys_ptrace` → читать память процессов.

---

## 6. Cron и таймеры

```bash
ls -la /etc/cron* /var/spool/cron/crontabs 2>/dev/null
cat /etc/crontab
systemctl list-timers --all
```

Ищи:

- скрипт, который root запускает по расписанию и который **ты можешь писать**;
- `*` в команде (`tar *`, `chown *`) → wildcard-инъекция;
- относительные пути → PATH hijack;
- `source` записываемого конфига → `script_audit.py --check-writable`.

---

## 7. Записываемые файлы и PATH

```bash
find / -writable -type f 2>/dev/null | grep -vE '^/(proc|sys|dev|tmp|run)'
echo $PATH
```

- root-скрипт вызывает `backup` без `/usr/bin/backup` → подложи свой в PATH;
- root-скрипт `source /srv/app/runtime.conf` → допиши команду;
- systemd unit с записываемым `ExecStart` → подмени.

```bash
python linux/script_audit.py /usr/local/sbin/reconcile --check-writable
```

---

## 8. Контейнер

```bash
bash linux/docker_audit.sh
```

Самое частое:

- `/var/run/docker.sock` → `docker run -v /:/host ... chroot /host`;
- `--privileged` → монтировать диск хоста;
- `--pid=host` → `nsenter -t 1 ...`;
- cgroup v1 + `cap_sys_admin` → `release_agent`;
- host-путь `/host` → читать напрямую.

Подробно — `DOCKER.md`.

---

## 9. Kubernetes

```bash
bash linux/k8s_audit.sh
python network/k8s_api.py --host https://ip:6443 --token T --list
python network/k8s_api.py --host ... --token T --secrets
```

Ищи token, namespace, secrets, privileged/hostPath поды.

---

## 10. SSH

Раздел `linux/` **не подключается** к SSH. Для этого системный `ssh`:

```bash
ssh user@host
ssh -i id_rsa user@host
ssh -o ProxyCommand="openssl s_client -connect host:443 -servername host -quiet" user@host
ssh -J jump@host target@internal
ssh -L 8080:localhost:80 user@host
```

Ключ с паролем:

```bash
ssh2john id_rsa > hash
john hash --wordlist=rockyou.txt
```

Подробно — `SSH.md`.

---

## 11. Чек-лист

- [ ] `id`, `uname -a`, `sudo -l`
- [ ] `privesc.sh`
- [ ] SUID/SGID + GTFObins
- [ ] capabilities
- [ ] cron/таймеры + записываемые скрипты
- [ ] записываемые конфиги у root-скриптов
- [ ] PATH
- [ ] docker.sock / privileged / host PID
- [ ] k8s token/secrets
- [ ] `.bash_history`, `.ssh`, конфиги, БД
- [ ] поиск `*flag*`, `CTF{`
- [ ] если ничего — ядро/версии сервисов (осторожно, только на своих стендах)

---

## 12. Что не входит

- Подключение к SSH — внешний `ssh`.
- Веб-эксплуатация — `WEB.md`.
- Крипта/стего/реверс — соответствующие разделы.
- Kernel-эксплойты — только если разрешено; здесь нет готовых эксплойтов.

---

## 13. WSL: свой Linux под рукой (Arch)

На Windows ELF не запускается, поэтому динамику (crackme, pwn, «а что оно
делает») смотрим внутри WSL-дистрибутива **Arch**. Он живёт на `F:\dev\wsl\archlinux`.

```powershell
wsl -d archlinux                 # обычный шелл (пользователь ctf, пароль ctf)
python linux/wsl.py info         # ядро, юзер, какие инструменты внутри
python linux/wsl.py run .\chall  # копирует в ~/inbox, chmod +x, запускает
python linux/wsl.py run .\chall -- --help
python linux/wsl.py run .\chall --dir      # вместе с соседними libc.so.6 / ld-linux
python linux/wsl.py run .\chall --arch auto   # aarch64/ARM -> qemu-aarch64/qemu-arm
python linux/wsl.py sh "checksec --file=~/inbox/chall"
python linux/wsl.py inbox        # что уже перенесено
python linux/wsl.py which gdb python3 r2
```

Внутри стоят `gdb` (+gef/pwndbg), `pwntools`, `checksec`, `patchelf`,
`radare2`, `rizin`, `ghidra`, `jadx`, `apktool`, `binwalk`, `qemu-user`,
`hashcat`, `john`, `nmap`, `sqlmap`, `ffuf`, `feroxbuster`, `nuclei`,
`volatility3`, `z3`, `paru` (AUR) и `fastfetch`.

```bash
ffuf -u http://host/FUZZ -w ~/wordlists/rockyou.txt          # словари с Windows
ffuf -u http://host/api/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc 200,301
```

Что это меняет для задач:

- crackme/pwn: `wsl.py run` → посмотреть поведение, `wsl.py sh "gdb ..."`;
- arm/aarch64: `wsl.py run bin --arch auto` сам выберет `qemu-aarch64` и
  поищет сисколл в `/usr/aarch64-linux-gnu` / `/usr/lib/aarch64-linux-gnu`.
  Если сисколла нет, будет подсказка поставить `aarch64-linux-gnu-glibc`
  (установка — только с разрешения). Статический ARM-бинарь идёт и без него;
- сервисные задачи: `wsl.py sh "nc localhost 1337"` / pwntools remote;
- «залить на цель»: `python3 -m http.server` внутри WSL.

**Доступ:** `C:` **не монтируется вообще**, остальной `F:` — тоже. Видны только
`F:\dev` (`/mnt/f/dev`) и `F:\AIproject` (`/mnt/f/AIproject`), и только туда
можно писать. Запуск файлов из любого места Windows — через `wsl.py`: он
копирует файл в Linux по stdin в `~/inbox`, диск `C:` при этом не монтируется.

```powershell
python linux/wsl.py run C:\Users\nispa\Downloads\chall      # -> ~/inbox/chall
python linux/wsl.py run C:\tasks\pwn --dir                  # весь каталог
python linux/wsl.py inbox                                   # что уже перенесено
```

Внутри Linux это `/home/ctf/inbox` — оттуда можно запускать, отлаживать,
копировать куда угодно (место ограничено диском WSL).

`cmd.exe`/`powershell.exe` из Linux не запускаются (interop выключен), так что
случайно «снести винду» не выйдет. Нужна ещё одна папка с записью — строка в
`/etc/fstab` (только прямые слэши: `F:/dev`, не `F:\dev`):

```bash
F:/some/path /mnt/f/some drvfs rw,metadata,uid=1000,gid=1000 0 0
sudo mount -a
```

**Диск ограничен 100 ГБ:** vhdx `F:\dev\wsl\arch100\ext4.vhdx`, внутри ext4 на
100 ГБ. Больше он не вырастет — при заполнении просто закончится место.
Обслуживание, чтобы не забивать:

```bash
paru -Syu          # обновить репы + AUR
paru -Sc           # сборочные кэши AUR
sudo pacman -Sc    # кэш пакетов
sudo fstrim -av    # отдать свободные блоки обратно
```

**WSL не работает в фоне:** systemd выключен, после последней команды
дистрибутив останавливается, VM гаснет через минуту простоя
(`vmIdleTimeout=60000`). Проверить: `wsl -l -v` → `Stopped`.

Если дистрибутив переехал/переименован — задай `WSL_DISTRO=<имя>`.
Скрипты установки лежат в `F:\dev\wsl\setup\` (`01-base.sh` … `44-interactive.sh`,
`40-audit.sh` — быстрый health-check) — их можно перезапускать, они идемпотентные.
