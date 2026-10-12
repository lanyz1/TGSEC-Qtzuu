#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-prometheus-unix-socket-dial}"
export PYTHONUNBUFFERED=1
export PROM_URL="${PROM_URL:-http://127.0.0.1:19390}"

LABEL="prometheus-unix-socket-dial"
WITNESS="PROMETHEUS-UNIX-SOCKET-DIAL-WITNESS"

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

if ! docker image inspect prom/prometheus:v3.15.0 >/dev/null 2>&1; then
  echo "== docker pull prom/prometheus:v3.15.0 =="
  docker pull prom/prometheus:v3.15.0 || fail_setup "prometheus-image-pull-failed"
fi
if ! docker image inspect python:3.13-slim >/dev/null 2>&1; then
  echo "== docker pull python:3.13-slim =="
  docker pull python:3.13-slim || fail_setup "python-image-pull-failed"
fi

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

echo "== wait prometheus 127.0.0.1:19390/-/ready =="
ok=0
for i in $(seq 1 45); do
  code="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 3 "${PROM_URL}/-/ready" || true)"
  if [[ "${code}" == "200" ]]; then
    ok=1
    echo "prometheus-ready attempt=${i}"
    break
  fi
  echo "prometheus-wait attempt=${i} http=${code}"
  sleep 2
done
if [[ "${ok}" != 1 ]]; then
  echo "== compose logs (not ready) =="
  docker compose -p "${COMPOSE_PROJECT_NAME}" logs --no-color --tail=80 || true
  fail_setup "prometheus-not-ready"
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
