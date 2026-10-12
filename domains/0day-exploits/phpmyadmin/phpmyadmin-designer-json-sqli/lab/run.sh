#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-phpmyadmin-designer-json-sqli}"
export PYTHONUNBUFFERED=1
LABEL="phpmyadmin-designer-json-sqli"
WITNESS="PMA-DESIGNER-JSON-SQLI-WITNESS"
PMA_URL="${PMA_URL:-http://127.0.0.1:19220}"

down() {
  echo "== docker compose down -v =="
  docker compose -p "${COMPOSE_PROJECT_NAME}" down -v --remove-orphans || true
}

trap down EXIT

echo "== docker compose down (clean) =="
down

echo "== docker compose up =="
up_ok=0
for attempt in $(seq 1 8); do
  if docker compose -p "${COMPOSE_PROJECT_NAME}" up -d; then
    up_ok=1
    break
  fi
  echo "compose-up-retry attempt=${attempt}"
  sleep 8
  down
done
if [[ "${up_ok}" != 1 ]]; then
  echo "FAIL ${LABEL} compose-up-failed ${WITNESS}" | tee poc-last-run.txt
  exit 1
fi

echo "== wait for phpMyAdmin ${PMA_URL} =="
ok=0
for i in $(seq 1 90); do
  code="$(curl -sS -o /tmp/pma-designer-json-sqli-ready.txt -w '%{http_code}' --max-time 8 "${PMA_URL}/index.php?route=/" || true)"
  if [[ "${code}" == "200" ]] && grep -qi 'phpmyadmin\|pma_username\|token' /tmp/pma-designer-json-sqli-ready.txt 2>/dev/null; then
    ok=1
    echo "IOC pma-up attempt=${i} http=${code}"
    break
  fi
  echo "pma-wait attempt=${i} http=${code}"
  sleep 2
done
if [[ "${ok}" != 1 ]]; then
  echo "FAIL ${LABEL} pma-not-ready ${WITNESS}" | tee poc-last-run.txt
  docker compose -p "${COMPOSE_PROJECT_NAME}" logs --tail=80 || true
  exit 1
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
