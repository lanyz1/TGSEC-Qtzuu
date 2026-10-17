#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-pfsense-api-export-key-get}"
export PYTHONUNBUFFERED=1
export MOCK_URL="${MOCK_URL:-http://127.0.0.1:19141}"
chmod +x poc.py

LABEL="PFSENSE-API-EXPORT-KEY-GET"
WITNESS="PFSENSE-API-EXPORT-KEY-GET-WITNESS"

down() {
  echo "== docker compose down -v =="
  docker compose -p "${COMPOSE_PROJECT_NAME}" down -v --remove-orphans || true
}

fail_setup() {
  local reason="$1"
  echo "FAIL ${LABEL} ${reason} ${WITNESS}" | tee poc-last-run.txt
  docker compose -p "${COMPOSE_PROJECT_NAME}" logs --no-color --tail=80 || true
  down
  exit 1
}

trap down EXIT

echo "== docker compose down (clean) =="
down

echo "== docker compose up --build =="
up_ok=0
for attempt in $(seq 1 8); do
  if docker compose -p "${COMPOSE_PROJECT_NAME}" up --build -d; then
    up_ok=1
    break
  fi
  echo "IOC compose-up-retry attempt=${attempt}"
  sleep 8
  down
done
if [[ "${up_ok}" != 1 ]]; then
  fail_setup "compose-up-failed"
fi

echo "== wait mock ${MOCK_URL}/health =="
ready=0
for i in $(seq 1 60); do
  code="$(curl -sS -o /tmp/pfsense-api-export-key-get-health.txt -w '%{http_code}' \
    --max-time 4 "${MOCK_URL}/health" || true)"
  if [[ "${code}" == "200" ]]; then
    ready=1
    echo "IOC mock-ready attempt=${i} http=${code}"
    break
  fi
  echo "IOC mock-wait attempt=${i} http=${code}"
  sleep 1
done
if [[ "${ready}" != 1 ]]; then
  fail_setup "mock-not-ready"
fi

echo "== poc.py =="
set +e
python3 ./poc.py | tee poc-last-run.txt
rc=${PIPESTATUS[0]}
set -e

if ! tail -n1 poc-last-run.txt 2>/dev/null | grep -qE '^(SUCCESS|FAIL) '; then
  echo "FAIL ${LABEL} poc-exit=${rc} ${WITNESS}" >> poc-last-run.txt
  rc=1
fi

exit "${rc}"
