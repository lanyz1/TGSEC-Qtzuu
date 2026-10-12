#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-mysql-install-component-scheme}"
export PYTHONUNBUFFERED=1

LABEL="mysql-install-component-scheme"
WITNESS="MYSQL-INSTALL-COMPONENT-SCHEME-WITNESS"
MYSQL_HOST="127.0.0.1"
MYSQL_PORT="18650"
LOG_FILE="poc-last-run.txt"

compose() {
  docker compose -p "${COMPOSE_PROJECT_NAME}" "$@"
}

down() {
  echo "== docker compose down -v =="
  compose down -v --remove-orphans || true
}

ensure_python_module() {
  local module="$1"
  if ! python3 -c "import ${module}" 2>/dev/null; then
    python3 -m pip install --break-system-packages "${module}"
  fi
}

wait_mysqld() {
  echo "== wait for mysqld ${MYSQL_HOST}:${MYSQL_PORT} =="
  local i
  for i in $(seq 1 90); do
    if compose exec -T mysql mysqladmin ping -h 127.0.0.1 -uroot -plabroot --silent >/dev/null 2>&1; then
      if python3 - <<'PY'
import pymysql
c = pymysql.connect(
    host="127.0.0.1",
    port=18650,
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

ensure_python_module pymysql
ensure_python_module cryptography

echo "== docker compose down (clean) =="
down

echo "== docker compose up --build =="
up_ok=0
for attempt in $(seq 1 5); do
  if compose up --build -d; then
    up_ok=1
    break
  fi
  echo "compose-up-retry attempt=${attempt}"
  sleep 8
  down
done
if [[ "${up_ok}" != 1 ]]; then
  echo "FAIL ${LABEL} compose-up-failed ${WITNESS}" | tee "${LOG_FILE}"
  exit 1
fi

if ! wait_mysqld; then
  echo "FAIL ${LABEL} mysqld-not-ready ${WITNESS}" | tee "${LOG_FILE}"
  compose logs --tail=80 || true
  exit 1
fi

echo "== poc.py =="
set +e
python3 ./poc.py | tee "${LOG_FILE}"
rc="${PIPESTATUS[0]}"
set -e

if ! tail -n1 "${LOG_FILE}" 2>/dev/null | grep -qE '^(SUCCESS|FAIL) '; then
  echo "FAIL ${LABEL} poc-exit=${rc} ${WITNESS}" >> "${LOG_FILE}"
  rc=1
fi

exit "${rc}"
