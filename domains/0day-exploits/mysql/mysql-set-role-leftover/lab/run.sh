#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-mysql-set-role-leftover}"
export PYTHONUNBUFFERED=1
LABEL="mysql-set-role-leftover"
WITNESS="MYSQL-SET-ROLE-LEFTOVER-WITNESS"
HOST="127.0.0.1"
PORT="18630"

need_py() {
  local mod="$1"
  if ! python3 -c "import ${mod}" 2>/dev/null; then
    python3 -m pip install --break-system-packages "${mod}"
  fi
}

down() {
  echo "== docker compose down -v =="
  docker compose -p "${COMPOSE_PROJECT_NAME}" down -v --remove-orphans || true
}

compose_up() {
  local attempt
  echo "== docker compose up --build =="
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

wait_ready() {
  local i
  echo "== wait for mysqld ${HOST}:${PORT} =="
  for i in $(seq 1 90); do
    if docker compose -p "${COMPOSE_PROJECT_NAME}" exec -T mysql \
      mysqladmin ping -h 127.0.0.1 -uroot -plabroot --silent >/dev/null 2>&1; then
      if python3 - <<'PY'
import pymysql

c = pymysql.connect(
    host="127.0.0.1",
    port=18630,
    user="root",
    password="labroot",
    connect_timeout=3,
)
cur = c.cursor()
cur.execute("SELECT 1")
cur.close()
c.close()
PY
      then
        echo "mysqld-ready attempt=${i}"
        return 0
      fi
    fi
    echo "mysqld-wait attempt=${i}"
    sleep 2
  done
  return 1
}

trap down EXIT

need_py pymysql
need_py cryptography

echo "== docker compose down (clean) =="
down

if ! compose_up; then
  echo "FAIL ${LABEL} compose-up-failed ${WITNESS}" | tee poc-last-run.txt
  exit 1
fi

if ! wait_ready; then
  echo "FAIL ${LABEL} mysqld-not-ready ${WITNESS}" | tee poc-last-run.txt
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
