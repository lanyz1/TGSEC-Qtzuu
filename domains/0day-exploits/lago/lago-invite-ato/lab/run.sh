#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-lago-invite-ato-lab}"
API="http://127.0.0.1:13000"

wait_graphql() {
  local i
  for i in $(seq 1 90); do
    if curl -fsS -o /dev/null "${API}/health"; then
      echo "IOC lago-up"
      return 0
    fi
    sleep 3
  done
  return 1
}

if [[ ! -f ./poc.py ]]; then
  echo "FAIL no poc.py"
  exit 1
fi
chmod +x ./poc.py

echo "== docker compose up (getlago/lago:v1.53.0, loopback) =="
docker compose -p "${COMPOSE_PROJECT_NAME}" up -d

echo "== wait for GraphQL =="
if ! wait_graphql; then
  echo "FAIL Lago API did not become ready on 127.0.0.1:13000"
  docker compose -p "${COMPOSE_PROJECT_NAME}" logs --tail=80
  exit 1
fi

# Give migrations / boot a beat after /health.
sleep 5

echo "== poc.py =="
python3 ./poc.py "${API}"
