#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-gitea-user-keys-idor}"
export PYTHONUNBUFFERED=1

BASE="${1:-http://127.0.0.1:18101}"
IMAGE="gitea/gitea:1.27.3"
KEYS_DIR="./keys"

chmod +x poc.py seed.py seed.sh

down() {
  echo "== docker compose down =="
  docker compose down --remove-orphans || true
}

wait_ready() {
  local i code
  echo "== wait for Gitea =="
  for i in $(seq 1 60); do
    code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "${BASE}/api/v1/version" || true)"
    if [[ "${code}" == "200" ]]; then
      echo "IOC gitea-up http=${code}"
      return 0
    fi
    echo "IOC wait i=${i} http=${code}"
    sleep 3
  done
  echo "FAIL Gitea did not become ready"
  docker compose logs --tail=80 gitea || true
  return 1
}

echo "== docker compose up (${IMAGE}, loopback) =="
docker compose up -d

if ! wait_ready; then
  exit 1
fi

cid="$(docker compose ps -q gitea)"
echo "== seed users + SSH keys =="
./seed.sh "${cid}" "${KEYS_DIR}"

echo "== poc.py =="
python3 poc.py "${BASE}"
