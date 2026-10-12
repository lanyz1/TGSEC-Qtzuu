#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-mysql-mysqldump-show-tables-overflow}"
export PYTHONUNBUFFERED=1

LABEL="mysql-mysqldump-show-tables-overflow"
WITNESS="MYSQL-DUMP-SHOW-TABLES-OVERFLOW-WITNESS"

down() {
  echo "== docker compose down -v =="
  docker compose -p "${COMPOSE_PROJECT_NAME}" down -v --remove-orphans || true
}

wait_ready() {
  local i
  echo "== wait for stub TCP 127.0.0.1:18600 and 18601 =="
  for i in $(seq 1 60); do
    if python3 - <<'PY'
import socket
for port in (18600, 18601):
    s = socket.create_connection(("127.0.0.1", port), 2)
    s.close()
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
  echo "FAIL ${LABEL} compose-up-failed ${WITNESS}" | tee poc-last-run.txt
  down
  exit 1
fi

if ! wait_ready; then
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
