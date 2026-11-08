#!/usr/bin/env bash
# flag_hunt.sh — поиск файлов-флагов на Linux-машине/в контейнере.
#
#   bash flag_hunt.sh
#   bash flag_hunt.sh --all
#   bash flag_hunt.sh /home /opt /srv
#
# Ищет имена flag, flag.txt, flag_<random>, *flag*, user.txt, root.txt,
# а также содержимое CTF{...}/flag{...}.
set -u

ALL=0
DIRS=()
for a in "$@"; do
  if [ "$a" = "--all" ]; then
    ALL=1
  else
    DIRS+=("$a")
  fi
done
if [ ${#DIRS[@]} -eq 0 ]; then
  if [ "$ALL" -eq 1 ]; then
    DIRS=(/)
  else
    DIRS=(/home /root /opt /srv /var/www /tmp /etc /usr/local /mnt /media)
  fi
fi

echo "===== 1. По именам ====="
for d in "${DIRS[@]}"; do
  [ -d "$d" ] || continue
  find "$d" -xdev -type f \
    \( -iname 'flag' -o -iname 'flag.*' -o -iname 'flag_*' -o -iname '*_flag' \
       -o -iname '*flag*' -o -iname 'user.txt' -o -iname 'root.txt' \) \
    2>/dev/null | while read -r f; do
      echo
      ls -la "$f" 2>/dev/null
      head -c 300 "$f" 2>/dev/null | tr '\0' ' '
      echo
    done
done

echo
echo "===== 2. По содержимому (небольшие текстовые файлы) ====="
for d in "${DIRS[@]}"; do
  [ -d "$d" ] || continue
  timeout 30 grep -RaoE --binary-files=without-match \
    '(CTF|ctf|flag|FLAG)[A-Za-z0-9_]*\{[^}]{1,200}\}' "$d" 2>/dev/null | head -50
done

echo
echo "===== 3. Быстрые места ====="
env 2>/dev/null | grep -Ei 'flag|ctf|secret' || true
for f in /flag /flag.txt /root/flag /root/flag.txt /home/*/user.txt /home/*/flag.txt; do
  [ -f "$f" ] && { echo "--- $f"; ls -la "$f"; head -c 300 "$f"; echo; }
done
ls -la /run/secrets 2>/dev/null && cat /run/secrets/* 2>/dev/null | head -20

echo
echo "===== 4. Если нет доступа ====="
echo "  проверь sudo -l, SUID (privesc.sh), группы, capabilities"
