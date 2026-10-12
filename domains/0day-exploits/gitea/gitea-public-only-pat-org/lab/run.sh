#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-gitea-public-only-pat-org}"
BASE="${1:-http://127.0.0.1:18132}"
USER="${GITEA_LAB_USER:-labuser}"
PASS="${GITEA_LAB_PASS:-LabPass123!}"
chmod +x poc.py

down() {
  echo "== docker compose down =="
  docker compose -p "${COMPOSE_PROJECT_NAME}" down || true
}

wait_ready() {
  echo "== wait for Gitea =="
  local i code
  for i in $(seq 1 60); do
    code="$(curl -s -o /tmp/gitea-public-only-pat-org-ver -w '%{http_code}' --max-time 5 "${BASE}/api/v1/version" || true)"
    if [[ "${code}" == "200" ]]; then
      echo "IOC gitea-up http=${code}"
      return 0
    fi
    echo "IOC wait i=${i} http=${code}"
    sleep 3
  done
  return 1
}

echo "== docker compose up (gitea/gitea:1.27.3, loopback :18132) =="
up_ok=0
for attempt in $(seq 1 10); do
  if docker compose -p "${COMPOSE_PROJECT_NAME}" up -d; then
    up_ok=1
    break
  fi
  echo "IOC compose-up-retry attempt=${attempt}"
  sleep 10
done
if [[ "${up_ok}" != 1 ]]; then
  echo "FAIL docker compose up" | tee poc-last-run.txt
  docker compose -p "${COMPOSE_PROJECT_NAME}" logs --tail=80 gitea || true
  down
  exit 1
fi

if ! wait_ready; then
  echo "FAIL Gitea did not become ready" | tee poc-last-run.txt
  docker compose -p "${COMPOSE_PROJECT_NAME}" logs --tail=80 gitea || true
  down
  exit 1
fi

cid="$(docker compose -p "${COMPOSE_PROJECT_NAME}" ps -q gitea)"
echo "== register user ${USER} =="
docker exec -u git "${cid}" gitea admin user create \
  --username "${USER}" \
  --password "${PASS}" \
  --email "${USER}@localhost.invalid" \
  --must-change-password=false >/dev/null 2>&1 || true
echo "IOC user-ready user=${USER}"

echo "== poc.py =="
set +e
python3 ./poc.py "${BASE}" "${USER}" "${PASS}" | tee poc-last-run.txt
rc=${PIPESTATUS[0]}
set -e
if [[ "${rc}" != 0 ]]; then
  echo "== gitea logs (tail) ==" | tee -a poc-last-run.txt
  docker compose -p "${COMPOSE_PROJECT_NAME}" logs --tail=80 gitea | tee -a poc-last-run.txt || true
fi
down
exit "${rc}"
