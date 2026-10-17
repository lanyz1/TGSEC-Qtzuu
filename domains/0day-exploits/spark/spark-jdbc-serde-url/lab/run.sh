#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-spark-jdbc-serde-url}"
export PYTHONUNBUFFERED=1
chmod +x poc.py

LABEL="SPARK-JDBC-SERDE-URL"
WITNESS="SPARK-JDBC-SERDE-URL-WITNESS"
HOST="127.0.0.1"
PORT="18960"
HTTP_PORT="18961"

down() {
  echo "== docker compose down -v =="
  docker compose -p "${COMPOSE_PROJECT_NAME}" down -v --remove-orphans || true
}

trap down EXIT

fail_setup() {
  local reason="$1"
  echo "FAIL ${LABEL} ${reason} ${WITNESS}" | tee poc-last-run.txt
  docker compose -p "${COMPOSE_PROJECT_NAME}" logs --no-color --tail=80 || true
  exit 1
}

echo "== docker compose down (clean) =="
down

rm -f oracle/pwned.txt oracle/hits.jsonl
mkdir -p oracle

echo "== docker compose up --build =="
up_ok=0
for attempt in $(seq 1 8); do
  if docker compose -p "${COMPOSE_PROJECT_NAME}" up --build -d; then
    up_ok=1
    break
  fi
  echo "IOC compose-up-retry attempt=${attempt}"
  sleep 8
  down
done
if [[ "${up_ok}" != 1 ]]; then
  fail_setup "compose-up-failed"
fi

echo "== wait oracle ${HOST}:${HTTP_PORT}/health =="
ready=0
for i in $(seq 1 60); do
  if python3 - <<PY
import urllib.request

urllib.request.urlopen("http://${HOST}:${HTTP_PORT}/health", timeout=2)
PY
  then
    ready=1
    echo "IOC oracle-ready attempt=${i}"
    break
  fi
  echo "IOC oracle-wait attempt=${i}"
  sleep 2
done
if [[ "${ready}" != 1 ]]; then
  fail_setup "oracle-not-ready"
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
