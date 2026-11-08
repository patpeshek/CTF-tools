#!/usr/bin/env bash
# k8s_audit.sh — аудит пода Kubernetes. Только чтение.
#
#   bash k8s_audit.sh | tee k8s.txt
set -u

SA=/var/run/secrets/kubernetes.io/serviceaccount
echo "===== 1. Service account ====="
ls -la "$SA" 2>/dev/null || echo "нет $SA"
if [ -f "$SA/token" ]; then
  echo "token length: $(wc -c < "$SA/token")"
  echo "namespace: $(cat "$SA/namespace" 2>/dev/null)"
  echo "--- JWT payload ---"
  python - <<'PY' 2>/dev/null || true
import base64, json
t = open('/var/run/secrets/kubernetes.io/serviceaccount/token').read().strip()
p = t.split('.')[1]
p += '=' * (-len(p) % 4)
print(json.dumps(json.loads(base64.urlsafe_b64decode(p)), indent=2))
PY
fi

echo
echo "===== 2. API server ====="
echo "KUBERNETES_SERVICE_HOST=${KUBERNETES_SERVICE_HOST:-}"
echo "KUBERNETES_SERVICE_PORT=${KUBERNETES_SERVICE_PORT:-}"
ls -la /etc/kubernetes 2>/dev/null || true
find / -maxdepth 4 -name "kubeconfig" 2>/dev/null | head

echo
echo "===== 3. Пробуем API ====="
if [ -f "$SA/token" ] && [ -n "${KUBERNETES_SERVICE_HOST:-}" ]; then
  TOKEN=$(cat "$SA/token")
  NS=$(cat "$SA/namespace" 2>/dev/null || echo default)
  BASE="https://${KUBERNETES_SERVICE_HOST}:${KUBERNETES_SERVICE_PORT:-443}"
  echo "--- pods ---"
  curl -s --cacert "$SA/ca.crt" -H "Authorization: Bearer $TOKEN" \
    "$BASE/api/v1/namespaces/$NS/pods" | head -c 4000
  echo
  echo "--- secrets ---"
  curl -s --cacert "$SA/ca.crt" -H "Authorization: Bearer $TOKEN" \
    "$BASE/api/v1/namespaces/$NS/secrets" | head -c 4000
  echo
fi

echo
echo "===== 4. Контейнер ====="
ls -la /.dockerenv 2>/dev/null || true
cat /proc/1/cgroup 2>/dev/null
capsh --print 2>/dev/null | head -20 || true
env | grep -Ei 'kube|token|secret|pass|key' || true

echo
echo "===== 5. Монтирования ====="
mount 2>/dev/null | grep -Ei 'kube|secret|config|host' | head -30
ls -la /var/run/secrets 2>/dev/null || true
cat /var/run/secrets/kubernetes.io/serviceaccount/namespace 2>/dev/null || true

echo
echo "===== 6. Что дальше ====="
echo "  есть token?      python network/k8s_api.py --host https://... --token ... --list"
echo "  secrets?         k8s_api.py --secrets"
echo "  privileged pod?  см. linux/DOCKER.md"
echo "  hostPath?        ищи в spec.volumes через API"
