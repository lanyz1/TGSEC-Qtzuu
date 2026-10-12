#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-phpmyadmin-auth-plugin-unquoted}"
export PYTHONUNBUFFERED=1
export PMA_URL="${PMA_URL:-http://127.0.0.1:19260}"

LABEL="phpmyadmin-auth-plugin-unquoted"
WITNESS="PMA-AUTH-PLUGIN-UNQUOTED-WITNESS"

down() {
  echo "== docker compose down -v =="
  docker compose -p "${COMPOSE_PROJECT_NAME}" down -v --remove-orphans || true
}

trap down EXIT

fail_setup() {
  local reason="$1"
  echo "FAIL ${LABEL} ${reason} ${WITNESS}" | tee poc-last-run.txt
  exit 1
}

echo "== docker compose down (clean) =="
trap - EXIT
down
trap down EXIT

echo "== docker compose up =="
up_ok=0
for attempt in $(seq 1 5); do
  if docker compose -p "${COMPOSE_PROJECT_NAME}" up -d; then
    up_ok=1
    break
  fi
  echo "compose-up-retry attempt=${attempt}"
  sleep 8
  down
done
if [[ "${up_ok}" != 1 ]]; then
  fail_setup "compose-up-failed"
fi

echo "== wait for ${PMA_URL}/index.php?route=/ =="
ok=0
for i in $(seq 1 90); do
  if curl -fsS -o /dev/null --max-time 5 "${PMA_URL}/index.php?route=/"; then
    ok=1
    echo "pma-ready attempt=${i}"
    break
  fi
  echo "pma-wait attempt=${i}"
  sleep 2
done
if [[ "${ok}" != 1 ]]; then
  echo "== compose logs (not ready) =="
  docker compose -p "${COMPOSE_PROJECT_NAME}" logs --no-color --tail=80 || true
  fail_setup "pma-not-ready"
fi

chmod +x poc.py
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
