#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-vsftpd-deny-file-brace-child}"
export PYTHONUNBUFFERED=1

LABEL="vsftpd-deny-file-brace-child"
WITNESS="VSFTPD-DENY-FILE-BRACE-CHILD-WITNESS"

down() {
  echo "== docker compose down -v =="
  docker compose -p "${COMPOSE_PROJECT_NAME}" down -v --remove-orphans || true
}

fail_setup() {
  local reason="$1"
  echo "FAIL ${LABEL} ${reason} ${WITNESS}" | tee poc-last-run.txt
  exit 1
}

trap down EXIT

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
  echo "== compose logs (up failed) =="
  docker compose -p "${COMPOSE_PROJECT_NAME}" logs --no-color --tail=80 || true
  fail_setup "compose-up-failed"
fi

echo "== wait for FTP 127.0.0.1:18710 =="
ok=0
for i in $(seq 1 220); do
  if python3 - <<'PY'
import socket
sock = socket.create_connection(("127.0.0.1", 18710), 2)
sock.close()
PY
  then
    ok=1
    echo "ftp-ready attempt=${i}"
    break
  fi
  echo "ftp-wait attempt=${i}"
  sleep 1
done
if [[ "${ok}" != 1 ]]; then
  echo "== compose logs (not ready) =="
  docker compose -p "${COMPOSE_PROJECT_NAME}" logs --no-color --tail=80 || true
  fail_setup "ftp-not-ready"
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
