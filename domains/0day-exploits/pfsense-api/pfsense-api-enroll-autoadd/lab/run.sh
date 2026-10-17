#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-pfsense-api-enroll-autoadd}"
export PYTHONUNBUFFERED=1
export SSH_HOST="${SSH_HOST:-127.0.0.1}"
export SSH_PORT="${SSH_PORT:-19111}"
export WITNESS="${WITNESS:-PFSENSE-API-ENROLL-AUTOADD-WITNESS}"

LABEL="PFSENSE-API-ENROLL-AUTOADD"

down() {
  echo "== docker compose down -v =="
  docker compose -p "${COMPOSE_PROJECT_NAME}" down -v --remove-orphans || true
}

fail_setup() {
  local reason="$1"
  echo "FAIL ${LABEL} ${reason} ${WITNESS}" | tee poc-last-run.txt
  docker compose -p "${COMPOSE_PROJECT_NAME}" logs --no-color --tail=80 || true
  exit 1
}

trap down EXIT

echo "== docker compose down (clean) =="
down

if [[ ! -x .venv/bin/python ]]; then
  echo "== python3 -m venv .venv + paramiko =="
  python3 -m venv .venv
  .venv/bin/pip install -q --upgrade pip
  .venv/bin/pip install -q "paramiko>=3.4,<4" || fail_setup "paramiko-install-failed"
fi
if ! .venv/bin/python -c "import paramiko" 2>/dev/null; then
  .venv/bin/pip install -q "paramiko>=3.4,<4" || fail_setup "paramiko-import-failed"
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

echo "== wait SSH banner ${SSH_HOST}:${SSH_PORT} =="
ok=0
for i in $(seq 1 90); do
  if .venv/bin/python - <<PY
import socket
import sys

host = "${SSH_HOST}"
port = int("${SSH_PORT}")
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.settimeout(3)
try:
    sock.connect((host, port))
    banner = sock.recv(256)
except OSError:
    raise SystemExit(1)
finally:
    sock.close()
raise SystemExit(0 if banner.startswith(b"SSH-") else 1)
PY
  then
    ok=1
    echo "sshd-ready attempt=${i}"
    break
  fi
  echo "sshd-wait attempt=${i}"
  sleep 1
done
if [[ "${ok}" != 1 ]]; then
  echo "== compose logs (not ready) =="
  docker compose -p "${COMPOSE_PROJECT_NAME}" logs --no-color --tail=120 || true
  fail_setup "sshd-not-ready"
fi

echo "== poc.py =="
set +e
.venv/bin/python ./poc.py | tee poc-last-run.txt
rc=${PIPESTATUS[0]}
set -e

if ! tail -n1 poc-last-run.txt 2>/dev/null | grep -qE '^(SUCCESS|FAIL) '; then
  echo "FAIL ${LABEL} poc-exit=${rc} ${WITNESS}" >> poc-last-run.txt
  rc=1
fi

exit "${rc}"
