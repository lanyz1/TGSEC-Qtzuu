#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-mysql-jdv-definer-sqli}"
export PYTHONUNBUFFERED=1

LABEL="mysql-jdv-definer-sqli"
WITNESS="MYSQL-JDV-DEFINER-SQLI-WITNESS"
MYSQL_HOST="127.0.0.1"
MYSQL_PORT="18640"
MYSQL_USER="root"
MYSQL_PASSWORD="labroot"

down() {
  echo "== docker compose down -v =="
  docker compose -p "${COMPOSE_PROJECT_NAME}" down -v --remove-orphans || true
}

ensure_py_deps() {
  if ! python3 -c "import pymysql" 2>/dev/null; then
    python3 -m pip install --break-system-packages pymysql
  fi
  if ! python3 -c "import cryptography" 2>/dev/null; then
    python3 -m pip install --break-system-packages cryptography
  fi
}

compose_up() {
  echo "== docker compose up --build =="
  local up_ok=0
  local attempt
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
    exit 1
  fi
}

wait_mysqld() {
  echo "== wait for mysqld ${MYSQL_HOST}:${MYSQL_PORT} =="
  local ok=0
  local i
  for i in $(seq 1 90); do
    if docker compose -p "${COMPOSE_PROJECT_NAME}" exec -T mysql \
      mysqladmin ping -h 127.0.0.1 -u"${MYSQL_USER}" -p"${MYSQL_PASSWORD}" --silent \
      >/dev/null 2>&1; then
      if MYSQL_HOST="${MYSQL_HOST}" MYSQL_PORT="${MYSQL_PORT}" \
        MYSQL_USER="${MYSQL_USER}" MYSQL_PASSWORD="${MYSQL_PASSWORD}" python3 - <<'PY'
import os

import pymysql

c = pymysql.connect(
    host=os.environ["MYSQL_HOST"],
    port=int(os.environ["MYSQL_PORT"]),
    user=os.environ["MYSQL_USER"],
    password=os.environ["MYSQL_PASSWORD"],
    connect_timeout=3,
)
cur = c.cursor()
cur.execute("SELECT 1")
cur.close()
c.close()
PY
      then
        ok=1
        echo "mysqld-ready attempt=${i}"
        break
      fi
    fi
    echo "mysqld-wait attempt=${i}"
    sleep 2
  done
  if [[ "${ok}" != 1 ]]; then
    echo "FAIL ${LABEL} mysqld-not-ready ${WITNESS}" | tee poc-last-run.txt
    docker compose -p "${COMPOSE_PROJECT_NAME}" logs --tail=80 || true
    exit 1
  fi
}

run_poc() {
  echo "== poc.py =="
  set +e
  python3 ./poc.py | tee poc-last-run.txt
  local rc=${PIPESTATUS[0]}
  set -e
  if ! tail -n1 poc-last-run.txt 2>/dev/null | grep -qE '^(SUCCESS|FAIL) '; then
    echo "FAIL ${LABEL} poc-exit=${rc} ${WITNESS}" >> poc-last-run.txt
    rc=1
  fi
  return "${rc}"
}

trap down EXIT
ensure_py_deps

echo "== docker compose down (clean) =="
down
compose_up
wait_mysqld
run_poc
exit $?
