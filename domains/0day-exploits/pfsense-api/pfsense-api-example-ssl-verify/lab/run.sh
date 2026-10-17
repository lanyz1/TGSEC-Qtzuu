#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-pfsense-api-example-ssl-verify}"
export PYTHONUNBUFFERED=1

LABEL="pfsense-api-example-ssl-verify"
WITNESS="PFSENSE-API-EXAMPLE-SSL-VERIFY-WITNESS"

down() {
  echo "== docker compose down -v =="
  docker compose -p "${COMPOSE_PROJECT_NAME}" down -v --remove-orphans || true
}

write_fail() {
  local reason="$1"
  echo "FAIL ${LABEL} ${reason} ${WITNESS}" | tee poc-last-run.txt
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

run_host_fallback=0
if [[ "${up_ok}" != 1 ]]; then
  echo "compose up failed; falling back to host python"
  run_host_fallback=1
fi

rc=1
if [[ "${run_host_fallback}" != 1 ]]; then
  echo "== wait for container =="
  ok=0
  for i in $(seq 1 30); do
    if docker compose -p "${COMPOSE_PROJECT_NAME}" exec -T lab true >/dev/null 2>&1; then
      ok=1
      break
    fi
    sleep 1
  done
  if [[ "${ok}" != 1 ]]; then
    echo "container not ready; falling back to host python"
    docker compose -p "${COMPOSE_PROJECT_NAME}" logs --no-color --tail=80 || true
    run_host_fallback=1
  fi
fi

echo "== poc.py =="
set +e
if [[ "${run_host_fallback}" == 1 ]]; then
  echo "host-fallback=yes"
  LAB_BIND_HOST=127.0.0.1 LAB_BIND_PORT=19191 LAB_CONNECT_HOST=127.0.0.1 \
    python3 ./poc.py | tee poc-last-run.txt
  rc=${PIPESTATUS[0]}
else
  docker compose -p "${COMPOSE_PROJECT_NAME}" exec -T lab python3 /lab/poc.py | tee poc-last-run.txt
  rc=${PIPESTATUS[0]}
fi
set -e

if ! tail -n1 poc-last-run.txt 2>/dev/null | grep -qE "^(SUCCESS|FAIL) "; then
  if [[ "${rc}" == 0 ]]; then
    write_fail "missing-status-line"
    rc=1
  else
    echo "FAIL ${LABEL} poc-exit=${rc} ${WITNESS}" >> poc-last-run.txt
  fi
fi

down
exit "${rc}"
