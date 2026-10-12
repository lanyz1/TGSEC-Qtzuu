#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-hyperswitch-unsigned-webhook}"
BASE="${1:-http://127.0.0.1:18082}"
HYPERSWITCH_TAG="2026.09.21.0"
SRC_DIR="hyperswitch-src"
POC="./poc.py"

down() {
  echo "== docker compose down =="
  docker compose -p "${COMPOSE_PROJECT_NAME}" down --remove-orphans || true
}

ensure_src() {
  if [[ ! -d "${SRC_DIR}/config" ]]; then
    echo "== clone Hyperswitch tag ${HYPERSWITCH_TAG} =="
    git clone --depth 1 --branch "${HYPERSWITCH_TAG}" \
      https://github.com/juspay/hyperswitch.git "${SRC_DIR}"
  fi
}

wait_ready() {
  echo "== wait for health =="
  local ok=0
  local i
  local code
  for i in $(seq 1 90); do
    code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 8 "${BASE}/health" || true)"
    if [[ "${code}" == "200" ]]; then
      echo "IOC hyperswitch-up http=${code}"
      ok=1
      break
    fi
    echo "IOC wait i=${i} http=${code}"
    sleep 5
  done
  if [[ "${ok}" != 1 ]]; then
    echo "FAIL Hyperswitch did not become ready on ${BASE}"
    docker compose -p "${COMPOSE_PROJECT_NAME}" logs --tail=80 hyperswitch-server
    exit 1
  fi
}

run_poc() {
  if [[ ! -f "${POC}" ]]; then
    echo "FAIL no poc.py"
    exit 1
  fi
  chmod +x "${POC}"
  echo "== poc.py =="
  python3 "${POC}" "${BASE}"
}

mkdir -p files
ensure_src

echo "== docker compose up (Hyperswitch router standalone, loopback) =="
docker compose -p "${COMPOSE_PROJECT_NAME}" up -d --build
wait_ready
run_poc
