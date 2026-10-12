#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-phpmyadmin-vqb-xss}"
export PYTHONUNBUFFERED=1

LABEL="phpmyadmin-vqb-xss"
WITNESS="PMA-VQB-XSS-WITNESS"

down() {
  echo "== docker compose down -v =="
  docker compose -p "${COMPOSE_PROJECT_NAME}" down -v --remove-orphans || true
}

fail_setup() {
  local reason="$1"
  echo "FAIL ${LABEL} ${reason} ${WITNESS}" | tee poc-last-run.txt
  down
  exit 1
}

echo "== docker compose down (clean) =="
down

echo "== docker compose build poc / up db pma =="
up_ok=0
for attempt in $(seq 1 5); do
  if docker compose -p "${COMPOSE_PROJECT_NAME}" build poc \
    && docker compose -p "${COMPOSE_PROJECT_NAME}" up -d db pma; then
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

echo "== wait for http://127.0.0.1:19250 =="
ok=0
for i in $(seq 1 90); do
  if python3 - <<'PY'
import urllib.request

urllib.request.urlopen("http://127.0.0.1:19250/index.php?route=/", timeout=3)
PY
  then
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

echo "== poc.py =="
set +e
docker compose -p "${COMPOSE_PROJECT_NAME}" run --rm -T --no-deps poc \
  | tee poc-last-run.txt
rc=${PIPESTATUS[0]}
set -e

if ! tail -n1 poc-last-run.txt 2>/dev/null | grep -qE '^(SUCCESS|FAIL) '; then
  echo "FAIL ${LABEL} poc-exit=${rc} ${WITNESS}" >> poc-last-run.txt
  rc=1
fi

down
exit "${rc}"
