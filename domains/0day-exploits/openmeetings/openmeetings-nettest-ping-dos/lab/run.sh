#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-om-g4-nettest}"
export OM_URL="${OM_URL:-https://127.0.0.1:18153}"
export PYTHONUNBUFFERED=1
chmod +x poc.py entrypoint.sh

WITNESS="OPENMEETINGS-NETTEST-PING-WITNESS"

down() {
  echo "== docker compose down -v =="
  docker compose -p "${COMPOSE_PROJECT_NAME}" down -v --remove-orphans || true
}

fail_run() {
  echo "FAIL ${WITNESS} $*" | tee poc-last-run.txt
  docker compose -p "${COMPOSE_PROJECT_NAME}" logs --no-color --tail=120 openmeetings db || true
  down
  exit 1
}

trap down EXIT

echo "== docker compose down (clean) =="
down

echo "== pull images =="
docker pull --platform linux/amd64 apache/openmeetings:min-9.1.0 || true
docker pull --platform linux/amd64 eclipse-temurin:21-jre-noble || true
docker pull mariadb:10.11 || true

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
  fail_run "compose-up-failed"
fi

echo "== wait ${OM_URL}/openmeetings/services/info/version (12 min) =="
ready=0
for i in $(seq 1 144); do
  if ! docker compose -p "${COMPOSE_PROJECT_NAME}" ps --status running --services 2>/dev/null | grep -qx openmeetings; then
    fail_run "openmeetings-exited"
  fi
  code="$(curl -skS -o /tmp/om-g4-nettest-version.txt -w '%{http_code}' --max-time 8 \
    "${OM_URL}/openmeetings/services/info/version" 2>/dev/null || true)"
  if [[ "${code}" == "200" ]] && grep -q '9.1.0' /tmp/om-g4-nettest-version.txt; then
    ready=1
    echo "IOC om-ready attempt=${i} http=${code}"
    break
  fi
  echo "IOC om-wait attempt=${i} http=${code}"
  sleep 5
done
if [[ "${ready}" != 1 ]]; then
  fail_run "openmeetings-not-ready"
fi

echo "== poc.py =="
set +e
python3 ./poc.py | tee poc-last-run.txt
rc=${PIPESTATUS[0]}
set -e

if ! tail -n1 poc-last-run.txt 2>/dev/null | grep -qE "^(SUCCESS|FAIL) ${WITNESS}"; then
  echo "FAIL ${WITNESS} poc-exit=${rc}" >> poc-last-run.txt
  rc=1
fi

exit "${rc}"
