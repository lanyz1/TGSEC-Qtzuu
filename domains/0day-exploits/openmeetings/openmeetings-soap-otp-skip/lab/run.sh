#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-om-g7-otp}"
export OM_URL="${OM_URL:-https://127.0.0.1:18157/openmeetings}"
chmod +x poc.py om-start.sh mysql_lab.py

down() {
  echo "== docker compose down -v =="
  docker compose -p "${COMPOSE_PROJECT_NAME}" down -v --remove-orphans || true
}

fail_run() {
  echo "FAIL OPENMEETINGS-SOAP-OTP-SKIP-WITNESS $*" | tee poc-last-run.txt
  docker compose -p "${COMPOSE_PROJECT_NAME}" logs --tail=120 om || true
  docker compose -p "${COMPOSE_PROJECT_NAME}" logs --tail=40 db || true
  exit 1
}

echo "== docker compose down (clean) =="
down
trap down EXIT

echo "== docker compose up =="
up_ok=0
for attempt in $(seq 1 12); do
  if docker compose -p "${COMPOSE_PROJECT_NAME}" up -d --build; then
    up_ok=1
    break
  fi
  echo "IOC compose-up-retry attempt=${attempt}"
  sleep 30
  down
done
if [[ "${up_ok}" != 1 ]]; then
  fail_run "compose up failed"
fi

echo "== wait HTTPS /services/info/version =="
ready=0
for i in $(seq 1 180); do
  code="$(curl -k -sS -o /tmp/om-g7-otp-health.txt -w '%{http_code}' --max-time 8 "${OM_URL}/services/info/version" || true)"
  if [[ "${code}" == "200" ]]; then
    ready=1
    echo "IOC om-ready attempt=${i} health=${code}"
    break
  fi
  echo "IOC om-wait attempt=${i} health=${code}"
  sleep 5
done
if [[ "${ready}" != 1 ]]; then
  fail_run "openmeetings not ready"
fi

echo "== poc.py =="
set +e
python3 ./poc.py | tee poc-last-run.txt
rc=${PIPESTATUS[0]}
set -e
if [[ "${rc}" != 0 ]]; then
  if ! tail -n1 poc-last-run.txt 2>/dev/null | grep -qE '^(SUCCESS|FAIL) '; then
    echo "FAIL OPENMEETINGS-SOAP-OTP-SKIP-WITNESS poc exit=${rc}" >> poc-last-run.txt
  fi
  docker compose -p "${COMPOSE_PROJECT_NAME}" logs --tail=80 om || true
fi

exit "${rc}"
