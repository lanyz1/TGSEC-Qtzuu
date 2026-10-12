#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-n8n-function-vm2}"
export PYTHONUNBUFFERED=1

LABEL="N8N-FUNCTION-VM2"
BASE="${1:-http://127.0.0.1:18201}"
LOG_FILE="poc-last-run.txt"

compose() {
  docker compose -p "${COMPOSE_PROJECT_NAME}" "$@"
}

down() {
  echo "== docker compose down -v =="
  compose down -v --remove-orphans || true
}

http_code() {
  local path="$1"
  local out="$2"
  curl -s -o "${out}" -w '%{http_code}' --max-time 5 "${BASE}${path}" || true
}

wait_ready() {
  echo "== wait for n8n readiness + REST on ${BASE} =="
  local i live ready settings
  for i in $(seq 1 90); do
    live="$(http_code "/healthz" /tmp/n8n-function-vm2-health)"
    ready="$(http_code "/healthz/readiness" /tmp/n8n-function-vm2-ready)"
    settings="$(http_code "/rest/settings" /tmp/n8n-function-vm2-settings)"
    if [[ "${ready}" == "200" && "${settings}" == "200" ]]; then
      echo "IOC n8n-up healthz=${live} readiness=${ready} settings=${settings}"
      return 0
    fi
    echo "IOC wait i=${i} healthz=${live} readiness=${ready} settings=${settings}"
    sleep 3
  done
  return 1
}

trap down EXIT

chmod +x poc.py

echo "== docker compose down (clean volume) =="
down

echo "== docker compose up (n8nio/n8n:2.42.0, loopback :18201) =="
up_ok=0
for attempt in $(seq 1 8); do
  if compose up -d --build; then
    up_ok=1
    break
  fi
  echo "IOC compose-up-retry attempt=${attempt}"
  sleep 15
done
if [[ "${up_ok}" != 1 ]]; then
  echo "FAIL ${LABEL} docker compose up" | tee "${LOG_FILE}"
  compose logs --tail=80 n8n || true
  exit 1
fi

if ! wait_ready; then
  echo "FAIL ${LABEL} n8n REST did not become ready on ${BASE}" | tee "${LOG_FILE}"
  compose logs --tail=80 n8n || true
  exit 1
fi

echo "== poc.py =="
set +e
python3 ./poc.py "${BASE}" | tee "${LOG_FILE}"
rc="${PIPESTATUS[0]}"
set -e
if [[ "${rc}" != 0 ]]; then
  echo "== n8n logs (tail) ==" | tee -a "${LOG_FILE}"
  compose logs --tail=80 n8n | tee -a "${LOG_FILE}" || true
fi
exit "${rc}"
