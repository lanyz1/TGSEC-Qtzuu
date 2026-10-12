#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-hyperswitch-payout-confirm-secret}"
BASE="${1:-http://127.0.0.1:18083}"
HYPERSWITCH_TAG="2026.09.21.0"
SRC_DIR="hyperswitch-src"

mkdir -p files

down() {
  docker compose down --remove-orphans || true
}

clone_src() {
  if [[ ! -d "${SRC_DIR}/config" ]]; then
    echo "== clone Hyperswitch tag ${HYPERSWITCH_TAG} =="
    git clone --depth 1 --branch "${HYPERSWITCH_TAG}" \
      https://github.com/juspay/hyperswitch.git "${SRC_DIR}"
  fi
}

resolve_poc() {
  if [[ -f poc.py ]]; then
    printf '%s\n' "./poc.py"
  else
    echo "FAIL no poc.py"
    exit 1
  fi
}

wait_ready() {
  local ok=0
  local i code
  echo "== wait for health =="
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
    docker compose logs --tail=80 hyperswitch-server
    exit 1
  fi
}

clone_src
POC="$(resolve_poc)"
chmod +x "${POC}"

echo "== docker compose up (Hyperswitch router standalone, loopback) =="
docker compose up -d --build

wait_ready

echo "== poc.py =="
python3 "${POC}" "${BASE}"
