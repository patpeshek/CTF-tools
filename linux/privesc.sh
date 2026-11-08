#!/usr/bin/env bash
# privesc.sh — быстрая разведка прав в Linux. Только чтение, ничего не меняет.
#
#   bash privesc.sh | tee privesc.txt
#
# Дальше смотри глазами: sudo -l, SUID, capabilities, cron, writable-конфиги,
# группы, docker.sock, PATH. Команды для найденных бинарей — в gtfobins.py.
set -u

echo "===== 1. Кто я ====="
id
uname -a
cat /etc/os-release 2>/dev/null | head -5

echo
echo "===== 2. sudo ====="
sudo -l 2>&1 || true

echo
echo "===== 3. SUID / SGID ====="
find / -xdev -perm -4000 -type f 2>/dev/null | sort
echo "--- SGID ---"
find / -xdev -perm -2000 -type f 2>/dev/null | sort

echo
echo "===== 4. Capabilities ====="
getcap -r / 2>/dev/null || true

echo
echo "===== 5. Cron / timers ====="
ls -la /etc/cron* 2>/dev/null || true
cat /etc/crontab 2>/dev/null || true
ls -la /var/spool/cron/crontabs 2>/dev/null || true
systemctl list-timers --all 2>/dev/null | head -30 || true

echo
echo "===== 6. Права на конфиги и скрипты ====="
for d in /etc /opt /srv /usr/local /var/www /home; do
  [ -d "$d" ] && find "$d" -maxdepth 3 -type f \( -name "*.conf" -o -name "*.sh" -o -name "*.service" \) \
    -writable 2>/dev/null | head -40
done

echo
echo "===== 7. Файлы, доступные на запись пользователю ====="
find / -xdev -writable -type f 2>/dev/null | grep -vE '^/(proc|sys|dev|tmp|run)' | head -60

echo
echo "===== 8. Группы и интересные файлы ====="
groups
ls -la /root 2>/dev/null || true
ls -la ~ 2>/dev/null || true
cat ~/.bash_history 2>/dev/null | tail -40 || true

echo
echo "===== 9. Docker / контейнеры ====="
ls -la /var/run/docker.sock /run/docker.sock 2>/dev/null || true
command -v docker >/dev/null && docker ps 2>/dev/null || true

echo
echo "===== 10. PATH и окружение ====="
echo "PATH=$PATH"
env | sort | head -40

echo
echo "===== 11. Свежие изменения ====="
find /etc /opt /srv /usr/local -type f -mmin -1440 2>/dev/null | head -30

echo
echo "===== 12. Что запущено от root ====="
ps aux 2>/dev/null | awk '$1=="root"' | head -30

echo
echo "[i] Дальше: python gtfobins.py --check \"$(sudo -l 2>/dev/null | grep -oE '/[^ ,]+' | xargs -n1 basename 2>/dev/null | tr '\n' ',' )\""
