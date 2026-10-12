#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-cakephp-cookie-suffix}"
export PYTHONUNBUFFERED=1
export CAKEPHP_COOKIE_PORT="${CAKEPHP_COOKIE_PORT:-19420}"

LABEL="cakephp-cookie-suffix"
WITNESS="CAKEPHP-COOKIE-SUFFIX-WITNESS"

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
down

echo "== docker compose up --build =="
up_ok=0
for attempt in $(seq 1 5); do
  if docker compose -p "${COMPOSE_PROJECT_NAME}" up --build -d; then
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

echo "== wait for 127.0.0.1:${CAKEPHP_COOKIE_PORT}/health =="
ok=0
for i in $(seq 1 90); do
  if python3 - <<PY
import urllib.request

urllib.request.urlopen(
    "http://127.0.0.1:${CAKEPHP_COOKIE_PORT}/health",
    timeout=2,
)
PY
  then
    ok=1
    echo "ready attempt=${i}"
    break
  fi
  echo "wait attempt=${i}"
  sleep 2
done
if [[ "${ok}" != 1 ]]; then
  echo "== compose logs (not ready) =="
  docker compose -p "${COMPOSE_PROJECT_NAME}" logs --no-color --tail=80 || true
  fail_setup "port-not-ready"
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
