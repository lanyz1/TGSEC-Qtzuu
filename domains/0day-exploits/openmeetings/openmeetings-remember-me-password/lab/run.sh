#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-om-g8-remember}"
export PYTHONUNBUFFERED=1
export OM_PORT="${OM_PORT:-18158}"
chmod +x poc.py entrypoint.sh

WITNESS="OPENMEETINGS-REMEMBER-ME-WITNESS"

down() {
  echo "== docker compose down -v =="
  docker compose -p "${COMPOSE_PROJECT_NAME}" down -v --remove-orphans || true
}

fail_setup() {
  local reason="$1"
  echo "FAIL ${WITNESS} ${reason}" | tee poc-last-run.txt
  docker compose -p "${COMPOSE_PROJECT_NAME}" logs --no-color --tail=80 openmeetings db || true
  down
  exit 1
}

trap down EXIT

echo "== docker compose down (clean) =="
down

echo "== pull images =="
docker pull --platform linux/amd64 apache/openmeetings:min-9.1.0 || true
docker pull --platform linux/amd64 eclipse-temurin:21-jre-noble || true
docker pull --platform linux/amd64 mariadb:10.11 || true

echo "== docker compose up =="
up_ok=0
for attempt in $(seq 1 12); do
  if docker compose -p "${COMPOSE_PROJECT_NAME}" up -d --build; then
    up_ok=1
    break
  fi
  echo "IOC compose-up-retry attempt=${attempt}"
  sleep 20
  down
done
if [[ "${up_ok}" != 1 ]]; then
  fail_setup "compose-up-failed"
fi

echo "== wait https://127.0.0.1:${OM_PORT}/openmeetings/services/info/version =="
ready=0
url="https://127.0.0.1:${OM_PORT}/openmeetings/services/info/version"
for i in $(seq 1 120); do
  code="$(curl -skS -o /tmp/om-g8-version.txt -w '%{http_code}' --max-time 8 "${url}" || true)"
  if [[ "${code}" == "200" ]] && grep -q '9.1' /tmp/om-g8-version.txt 2>/dev/null; then
    ready=1
    echo "IOC om-ready attempt=${i} http=${code}"
    break
  fi
  echo "IOC om-wait attempt=${i} http=${code}"
  sleep 5
done
if [[ "${ready}" != 1 ]]; then
  fail_setup "om-not-ready"
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

if grep -Fq "1Q2w3e4r5t^y" poc-last-run.txt; then
  echo "FAIL ${WITNESS} password-leaked-in-log" | tee poc-last-run.txt
  rc=1
fi

exit "${rc}"
