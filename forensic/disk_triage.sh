#!/usr/bin/env bash
# disk_triage.sh — быстрый разбор образа диска. Запускать в Linux/Kali/WSL от root.
#
#   sudo bash disk_triage.sh suspicious_disk.img
#
# Что делает: определяет ФС, монтирует только для чтения, показывает содержимое,
# ищет удалённые файлы через photorec, отдельно обрабатывает LUKS.
set -u

IMG="${1:?usage: disk_triage.sh <image>}"
MNT="/mnt/triage_$$"

echo "=== 1. Тип файла ==="
file "$IMG"

echo "=== 2. Таблица разделов (если есть) ==="
fdisk -l "$IMG" 2>/dev/null || true

echo "=== 3. LUKS? ==="
if file "$IMG" | grep -qi luks; then
  echo "LUKS-образ. Пароль может быть неполным: пробуй брут по маске (две * = 2 символа)."
  echo "  cryptsetup luksOpen $IMG secure_disk"
  echo "  mount /dev/mapper/secure_disk $MNT"
  echo "  (после работы: umount $MNT && cryptsetup close secure_disk)"
  exit 0
fi

echo "=== 4. Монтируем read-only ==="
mkdir -p "$MNT"
mount -o ro,loop "$IMG" "$MNT" && {
  echo "--- файлы ---"
  ls -laR "$MNT" | head -200
  echo "--- скрытые и .bash_history ---"
  find "$MNT" -name ".*" -o -name "*.txt" -o -name "*.py" 2>/dev/null | head -50
  umount "$MNT"
} || echo "[-] mount не удался (может быть не ext4 или нужен offset раздела)"

echo "=== 5. Восстановление удалённого (photorec) ==="
echo "  photorec $IMG        # интерактивно: выбираешь раздел, File Opt, ищешь jpg/txt/zip"
echo "  testdisk $IMG        # если нужно восстановить раздел"

echo "=== 6. Строки и флаги без монтирования ==="
strings -a "$IMG" | grep -Eai 'CTF\{|ctf\{|flag\{|password|passwd' | head -50

rmdir "$MNT" 2>/dev/null || true
