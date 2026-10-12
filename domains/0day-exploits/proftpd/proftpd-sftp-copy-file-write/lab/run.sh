#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-proftpd-sftp-copy-file-write}"
export PYTHONUNBUFFERED=1

LABEL="PROFTPD-SFTP-COPY-FILE-WRITE"
WITNESS="PROFTPD-SFTP-COPY-FILE-WRITE-WITNESS"

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

if [[ ! -d .venv ]]; then
  echo "== python venv =="
  python3 -m venv .venv
fi
# shellcheck disable=SC1091
source .venv/bin/activate
if ! python3 -c "import paramiko" 2>/dev/null; then
  echo "== pip install paramiko =="
  python3 -m pip install --upgrade pip
  python3 -m pip install "paramiko>=3.4"
fi

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
  fail_setup "compose-up-failed"
fi

echo "== wait for SFTP 127.0.0.1:18710 =="
ok=0
for i in $(seq 1 90); do
  if python3 - <<'PY'
import socket
sock = socket.create_connection(("127.0.0.1", 18710), 2)
sock.settimeout(2)
banner = sock.recv(256)
sock.close()
raise SystemExit(0 if banner.startswith(b"SSH-") else 1)
PY
  then
    ok=1
    echo "sftp-ready attempt=${i}"
    break
  fi
  echo "sftp-wait attempt=${i}"
  sleep 2
done
if [[ "${ok}" != 1 ]]; then
  echo "== compose logs (not ready) =="
  docker compose -p "${COMPOSE_PROJECT_NAME}" logs --no-color --tail=80 || true
  fail_setup "sftp-not-ready"
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
