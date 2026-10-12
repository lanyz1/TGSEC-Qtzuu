#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-mysql-mysqlbinlog-raw-path}"
export PYTHONUNBUFFERED=1
LABEL="mysql-mysqlbinlog-raw-path"
WITNESS="MYSQL-BINLOG-RAW-WITNESS"
CONTROL_PUBLISH=18620
TRAVERSAL_PUBLISH=18621

down() {
  echo "== docker compose down -v =="
  docker compose -p "${COMPOSE_PROJECT_NAME}" down -v --remove-orphans || true
}

fail_run() {
  echo "FAIL ${LABEL} ${1} ${WITNESS}" | tee poc-last-run.txt
}

wait_ready() {
  local i
  echo "== wait for stub TCP 127.0.0.1:${CONTROL_PUBLISH} and ${TRAVERSAL_PUBLISH} =="
  for i in $(seq 1 60); do
    if python3 - "${CONTROL_PUBLISH}" "${TRAVERSAL_PUBLISH}" <<'PY'
import socket
import sys

for port in map(int, sys.argv[1:]):
    sock = socket.create_connection(("127.0.0.1", port), 2)
    sock.close()
PY
    then
      echo "stub-ready attempt=${i}"
      return 0
    fi
    echo "stub-wait attempt=${i}"
    sleep 1
  done
  return 1
}

echo "== prepare work dirs =="
mkdir -p work/oracle work/binlogs
find work -type f -name 'mysql-bin.*' -delete || true
find work -type f -name "*${WITNESS}*" -delete || true

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
  fail_run "compose-up-failed"
  down
  exit 1
fi

if ! wait_ready; then
  fail_run "stub-not-ready"
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
