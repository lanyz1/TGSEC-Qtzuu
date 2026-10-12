#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-openlitespeed-dup-cookie-litespeed-role}"
export PYTHONUNBUFFERED=1

LABEL="openlitespeed-dup-cookie-litespeed-role"
WITNESS="OLS-DUP-COOKIE-LITESPEED-ROLE-WITNESS"
OLS_IMAGE_84="litespeedtech/openlitespeed:1.9.3-lsphp84"
OLS_IMAGE_83="litespeedtech/openlitespeed:1.9.3-lsphp83"
READY_URL="http://127.0.0.1:18750/cookie.php"

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

OLS_IMAGE="${OLS_IMAGE_84}"
echo "== docker pull ${OLS_IMAGE} =="
if ! docker pull "${OLS_IMAGE}"; then
  echo "pull-failed ${OLS_IMAGE}; trying ${OLS_IMAGE_83}"
  OLS_IMAGE="${OLS_IMAGE_83}"
  docker pull "${OLS_IMAGE}" || fail_setup "ols-image-pull-failed"
fi
export OLS_IMAGE

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

echo "== wait ${READY_URL} =="
ok=0
for i in $(seq 1 90); do
  if python3 - <<'PY'
import socket

req = (
    b"GET /cookie.php HTTP/1.1\r\n"
    b"Host: 127.0.0.1:18750\r\n"
    b"Connection: close\r\n"
    b"\r\n"
)
with socket.create_connection(("127.0.0.1", 18750), 3) as sock:
    sock.settimeout(5)
    sock.sendall(req)
    data = sock.recv(64)
if not data.startswith(b"HTTP/"):
    raise SystemExit(1)
PY
  then
    ok=1
    echo "ols-ready attempt=${i}"
    break
  fi
  echo "ols-wait attempt=${i}"
  sleep 2
done
if [[ "${ok}" != 1 ]]; then
  echo "== compose logs (not ready) =="
  docker compose -p "${COMPOSE_PROJECT_NAME}" logs --no-color --tail=80 || true
  fail_setup "ols-not-ready"
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
