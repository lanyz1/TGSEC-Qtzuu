#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-n8n-databricks-path-join}"

N8N_URL="http://127.0.0.1:18202"
MOCK_URL="http://127.0.0.1:18203"
HEALTH_TMP="/tmp/n8n-databricks-path-join-health"

down() {
  echo "== docker compose down =="
  docker compose down -v || true
}

write_fail() {
  local reason="$1"
  echo "FAIL ${reason}" | tee poc-last-run.txt
  echo "FAIL N8N-DBX-PATH-JOIN" | tee -a poc-last-run.txt
}

wait_n8n() {
  local i code
  for i in $(seq 1 90); do
    code="$(curl -s -o "${HEALTH_TMP}" -w '%{http_code}' --max-time 5 "${N8N_URL}/healthz" || true)"
    if [[ "${code}" == "200" ]]; then
      echo "IOC n8n-up http=${code}"
      return 0
    fi
    echo "IOC wait-n8n i=${i} http=${code}"
    sleep 3
  done
  return 1
}

wait_mock() {
  local i code
  for i in $(seq 1 30); do
    code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "${MOCK_URL}/health" || true)"
    if [[ "${code}" == "200" ]]; then
      echo "IOC mock-up http=${code}"
      return 0
    fi
    echo "IOC wait-mock i=${i} http=${code}"
    sleep 2
  done
  return 1
}

chmod +x poc.py

echo "== docker compose up (n8nio/n8n:2.42.0 + mock, loopback :18202/:18203) =="
up_ok=0
for attempt in $(seq 1 8); do
  if docker compose up -d --build; then
    up_ok=1
    break
  fi
  echo "IOC compose-up-retry attempt=${attempt}"
  sleep 10
done
if [[ "${up_ok}" != 1 ]]; then
  write_fail "docker compose up"
  docker compose logs --tail=80 || true
  down
  exit 1
fi

echo "== wait for n8n =="
if ! wait_n8n; then
  write_fail "n8n did not become ready"
  docker compose logs --tail=120 n8n | tee -a poc-last-run.txt || true
  down
  exit 1
fi

echo "== wait for mock =="
if ! wait_mock; then
  write_fail "mock did not become ready"
  docker compose logs --tail=80 mock | tee -a poc-last-run.txt || true
  down
  exit 1
fi

echo "== poc.py =="
set +e
python3 poc.py "${N8N_URL}" "${MOCK_URL}" | tee poc-last-run.txt
rc=${PIPESTATUS[0]}
set -e
if [[ "${rc}" != 0 ]]; then
  echo "== compose logs (tail) ==" | tee -a poc-last-run.txt
  docker compose logs --tail=120 n8n mock | tee -a poc-last-run.txt || true
fi
down
exit "${rc}"
