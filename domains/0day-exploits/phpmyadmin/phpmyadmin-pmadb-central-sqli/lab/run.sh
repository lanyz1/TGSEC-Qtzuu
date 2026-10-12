#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-phpmyadmin-pmadb-central-sqli}"
export PYTHONUNBUFFERED=1
export PMA_URL="${PMA_URL:-http://127.0.0.1:19210}"

LABEL="phpmyadmin-pmadb-central-sqli"
WITNESS="PMA-PMADB-CENTRAL-SQLI-WITNESS"

chmod +x poc.py

down() {
  echo "== docker compose down -v =="
  docker compose -p "${COMPOSE_PROJECT_NAME}" down -v --remove-orphans || true
}

trap down EXIT

fail_setup() {
  local reason="$1"
  echo "FAIL ${LABEL} ${reason} ${WITNESS}" | tee poc-last-run.txt
  docker compose -p "${COMPOSE_PROJECT_NAME}" logs --no-color --tail=80 || true
  exit 1
}

echo "== docker compose down (clean) =="
down

echo "== docker compose up --build =="
up_ok=0
for attempt in $(seq 1 5); do
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

echo "== wait for phpMyAdmin ${PMA_URL} =="
ready=0
for i in $(seq 1 90); do
  code="$(curl -sS -o /tmp/pma-central-sqli-ready.txt -w '%{http_code}' --max-time 8 "${PMA_URL}/index.php?route=/" || true)"
  if [[ "${code}" == "200" ]]; then
    ready=1
    echo "IOC pma-up attempt=${i} http=${code}"
    break
  fi
  echo "IOC pma-wait attempt=${i} http=${code}"
  sleep 2
done
if [[ "${ready}" != 1 ]]; then
  fail_setup "pma-not-ready"
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
