#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

LABEL="mysql-mysqldump-tab-path"
WITNESS="MYSQL-DUMP-TAB-TRAVERSAL-WITNESS"
export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-${LABEL}}"
export PYTHONUNBUFFERED=1
LOOPBACK_HOST="127.0.0.1"
PUB_CONTROL_PORT=18610
PUB_TRAVERSAL_PORT=18611

down() {
  echo "== docker compose down -v =="
  docker compose -p "${COMPOSE_PROJECT_NAME}" down -v --remove-orphans || true
}

compose_up() {
  local attempt
  for attempt in $(seq 1 5); do
    if docker compose -p "${COMPOSE_PROJECT_NAME}" up --build -d; then
      return 0
    fi
    echo "compose-up-retry attempt=${attempt}"
    sleep 8
    down
  done
  return 1
}

wait_stub() {
  local attempt
  export WAIT_HOST="${LOOPBACK_HOST}"
  export WAIT_PORTS="${PUB_CONTROL_PORT} ${PUB_TRAVERSAL_PORT}"
  for attempt in $(seq 1 60); do
    if python3 - <<'PY'
import os
import socket

host = os.environ["WAIT_HOST"]
for port in os.environ["WAIT_PORTS"].split():
    sock = socket.create_connection((host, int(port)), 2)
    sock.close()
PY
    then
      echo "stub-ready attempt=${attempt}"
      return 0
    fi
    echo "stub-wait attempt=${attempt}"
    sleep 1
  done
  return 1
}

echo "== prepare work dirs =="
mkdir -p work/tabdir work/oracle
find work -type f -name '*.sql' -delete || true
find work -type f -name "*${WITNESS}*" -delete || true

echo "== docker compose down (clean) =="
down

echo "== docker compose up --build =="
if ! compose_up; then
  echo "FAIL ${LABEL} compose-up-failed ${WITNESS}" | tee poc-last-run.txt
  down
  exit 1
fi

echo "== wait for stub TCP ${LOOPBACK_HOST}:${PUB_CONTROL_PORT} and ${PUB_TRAVERSAL_PORT} =="
if ! wait_stub; then
  echo "FAIL ${LABEL} stub-not-ready ${WITNESS}" | tee poc-last-run.txt
  docker compose -p "${COMPOSE_PROJECT_NAME}" logs --tail=80 || true
  down
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

down
exit "${rc}"
