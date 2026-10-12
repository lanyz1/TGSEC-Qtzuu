#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-postgres-basebackup-symlink}"
export PYTHONUNBUFFERED=1

LABEL="postgres-basebackup-symlink"
WITNESS="POSTGRES-BASEBACKUP-SYMLINK-WITNESS"

down() {
  echo "== docker compose down -v =="
  docker compose -p "${COMPOSE_PROJECT_NAME}" down -v --remove-orphans || true
}

fail_setup() {
  local reason="$1"
  echo "FAIL ${LABEL} ${reason} ${WITNESS}" | tee poc-last-run.txt
  down
  exit 1
}

trap down EXIT

echo "== prepare work dirs =="
rm -rf work
mkdir -p work/dest work/oracle

echo "== docker compose down (clean) =="
down

if ! docker image inspect postgres:18.6 >/dev/null 2>&1; then
  echo "== docker pull postgres:18.6 =="
  docker pull postgres:18.6 || fail_setup "image-pull-failed"
fi

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

echo "== wait for source TCP 127.0.0.1:19370 =="
ok=0
for i in $(seq 1 60); do
  if python3 - <<'PY'
import socket
sock = socket.create_connection(("127.0.0.1", 19370), 2)
sock.close()
PY
  then
    ok=1
    echo "source-ready attempt=${i}"
    break
  fi
  echo "source-wait attempt=${i}"
  sleep 1
done
if [[ "${ok}" != 1 ]]; then
  echo "== compose logs (not ready) =="
  docker compose -p "${COMPOSE_PROJECT_NAME}" logs --no-color --tail=80 || true
  fail_setup "source-not-ready"
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
