#!/usr/bin/env bash
# Запуск локального сайта. Окно/терминал = сервер: закрыл — сервер умер.
set -euo pipefail
cd "$(dirname "$0")"

PORT="${PORT:-8771}"
BIND="${BIND:-127.0.0.1}"
export PORT BIND

if command -v python3 >/dev/null 2>&1; then
  PY=python3
elif command -v python >/dev/null 2>&1; then
  PY=python
else
  echo "[x] python3 не найден. Установи Python 3 и добавь его в PATH." >&2
  exit 1
fi

# health отвечает {"ok": true, ...} — тогда сайт уже работает
health_ok() {
  local body=""
  if command -v curl >/dev/null 2>&1; then
    body="$(curl -s -m 2 "http://127.0.0.1:${PORT}/health" 2>/dev/null || true)"
  else
    body="$("$PY" -c 'import sys,urllib.request
u="http://127.0.0.1:%s/health" % sys.argv[1]
sys.stdout.write(urllib.request.urlopen(u, timeout=2).read().decode("utf-8","replace"))' "$PORT" 2>/dev/null || true)"
  fi
  case "$body" in
    *'"ok"'*) return 0 ;;
    *) return 1 ;;
  esac
}

if health_ok; then
  echo "[+] Сайт уже запущен на http://127.0.0.1:${PORT}/"
  if command -v xdg-open >/dev/null 2>&1; then
    xdg-open "http://127.0.0.1:${PORT}/" >/dev/null 2>&1 || true
  fi
  exit 0
fi

echo "[+] Запускаю сайт: http://127.0.0.1:${PORT}/"
echo "    Этот терминал = сервер. Ctrl+C или закрытие окна останавливает его."

if command -v xdg-open >/dev/null 2>&1; then
  ( sleep 2; xdg-open "http://127.0.0.1:${PORT}/" >/dev/null 2>&1 || true ) &
fi

exec "$PY" -u site/app.py
