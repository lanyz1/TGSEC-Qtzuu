#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-grafana-gitsync-dns-rebind}"
export GRAFANA_URL="${GRAFANA_URL:-http://127.0.0.1:19360}"
export DNS_URL="${DNS_URL:-http://127.0.0.1:19361}"
export ORACLE_URL="${ORACLE_URL:-http://127.0.0.1:19362}"
export LOCAL_ORACLE_URL="${LOCAL_ORACLE_URL:-http://127.0.0.1:19363}"
export PYTHONUNBUFFERED=1
chmod +x poc.py

LABEL="GRAFANA-GITSYNC-DNS-REBIND"
WITNESS="GRAFANA-GITSYNC-DNS-REBIND-WITNESS"

down() {
  echo "== docker compose down -v =="
  docker compose -p "${COMPOSE_PROJECT_NAME}" down -v --remove-orphans || true
}

fail_setup() {
  echo "FAIL ${LABEL} $* ${WITNESS}" | tee poc-last-run.txt
  docker compose -p "${COMPOSE_PROJECT_NAME}" logs --no-color --tail=80 || true
  down
  exit 1
}

trap down EXIT

echo "== docker compose down (clean) =="
down

echo "== docker compose up --build =="
up_ok=0
for attempt in $(seq 1 8); do
  if docker compose -p "${COMPOSE_PROJECT_NAME}" up --build -d; then
    up_ok=1
    break
  fi
  echo "IOC compose-up-retry attempt=${attempt}"
  sleep 20
  down
done
if [[ "${up_ok}" != 1 ]]; then
  fail_setup "compose up failed"
fi

echo "== wait grafana /api/health =="
ready=0
for i in $(seq 1 90); do
  code="$(curl -sS -o /tmp/grafana-gitsync-health.txt -w '%{http_code}' --max-time 8 "${GRAFANA_URL}/api/health" || true)"
  if [[ "${code}" == "200" ]]; then
    ready=1
    echo "IOC grafana-ready attempt=${i} http=${code}"
    break
  fi
  echo "IOC grafana-wait attempt=${i} http=${code}"
  sleep 2
done
if [[ "${ready}" != 1 ]]; then
  fail_setup "grafana not ready"
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
