#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-lago-stripe-invoice-idor}"
BASE="${1:-http://127.0.0.1:13001}"

chmod +x seed_stripe.rb

if [[ ! -f poc.py ]]; then
  echo "FAIL no poc.py"
  exit 1
fi
chmod +x poc.py

down() {
  docker compose -p "${COMPOSE_PROJECT_NAME}" down --remove-orphans || true
}

wait_ready() {
  local i
  for i in $(seq 1 90); do
    if curl -fsS -o /dev/null "${BASE}/health"; then
      echo "IOC lago-up"
      return 0
    fi
    echo "IOC wait i=${i}"
    sleep 3
  done
  return 1
}

echo "== docker compose up (getlago/lago:v1.53.0, loopback) =="
docker compose -p "${COMPOSE_PROJECT_NAME}" up -d

echo "== wait for GraphQL =="
if ! wait_ready; then
  echo "FAIL Lago API did not become ready on ${BASE}"
  docker compose -p "${COMPOSE_PROJECT_NAME}" logs --tail=80
  exit 1
fi
sleep 5

echo "== poc.py =="
python3 ./poc.py "${BASE}"
