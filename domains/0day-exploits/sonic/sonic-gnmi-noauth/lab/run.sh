#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-sonic-gnmi-noauth}"
export PYTHONUNBUFFERED=1
chmod +x poc.py

PY=python3

down() {
  echo "== docker compose down -v =="
  docker compose -p "${COMPOSE_PROJECT_NAME}" down -v --remove-orphans || true
}

ensure_grpc() {
  if "${PY}" -c "import grpc" 2>/dev/null; then
    return 0
  fi
  echo "== venv grpcio =="
  if [[ ! -d .venv ]]; then
    "${PY}" -m venv .venv
  fi
  # shellcheck disable=SC1091
  source .venv/bin/activate
  PY=python3
  pip install -q --upgrade pip
  pip install -q grpcio protobuf
}

listeners_ready() {
  "${PY}" - <<'PY'
import socket
import sys

for port in (18080, 18081):
    sock = socket.socket()
    sock.settimeout(2)
    try:
        sock.connect(("127.0.0.1", port))
    except OSError:
        sys.exit(1)
    finally:
        sock.close()
sys.exit(0)
PY
}

ensure_grpc

echo "== docker compose down (clean) =="
down

echo "== docker compose up --build (loopback :18080/:18081) =="
up_ok=0
for attempt in $(seq 1 6); do
  if docker compose -p "${COMPOSE_PROJECT_NAME}" up -d --build; then
    up_ok=1
    break
  fi
  echo "IOC compose-up-retry attempt=${attempt}"
  sleep 12
done
if [[ "${up_ok}" != 1 ]]; then
  echo "FAIL SONIC-GNMI-NOAUTH docker compose up" | tee poc-last-run.txt
  docker compose -p "${COMPOSE_PROJECT_NAME}" logs --tail=80 gnmi || true
  down
  exit 1
fi

echo "== wait for ToR :18080 and DPU :18081 =="
ok=0
for i in $(seq 1 60); do
  if listeners_ready; then
    echo "IOC gnmi-up tor=18080 dpu=18081"
    ok=1
    break
  fi
  echo "IOC wait i=${i}"
  sleep 2
done
if [[ "${ok}" != 1 ]]; then
  echo "FAIL SONIC-GNMI-NOAUTH listeners did not become ready" | tee poc-last-run.txt
  docker compose -p "${COMPOSE_PROJECT_NAME}" logs --tail=80 gnmi || true
  down
  exit 1
fi

echo "== poc.py =="
set +e
"${PY}" poc.py | tee poc-last-run.txt
rc=${PIPESTATUS[0]}
set -e
if [[ "${rc}" != 0 ]]; then
  echo "== gnmi logs (tail) ==" | tee -a poc-last-run.txt
  docker compose -p "${COMPOSE_PROJECT_NAME}" logs --tail=80 gnmi | tee -a poc-last-run.txt || true
fi
down
exit "${rc}"
