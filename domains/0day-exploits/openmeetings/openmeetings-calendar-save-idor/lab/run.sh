#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-om-g1-calendar}"
export OM_HOST="${OM_HOST:-127.0.0.1}"
export OM_PORT="${OM_PORT:-18150}"
chmod +x poc.py entrypoint.sh || true

down() {
  echo "== docker compose down -v =="
  docker compose -p "${COMPOSE_PROJECT_NAME}" down -v --remove-orphans || true
}

fail_run() {
  echo "FAIL OPENMEETINGS-CALENDAR-SAVE-WITNESS $*" | tee poc-last-run.txt
  docker compose -p "${COMPOSE_PROJECT_NAME}" logs --tail=120 openmeetings db || true
  down
  exit 1
}

echo "== docker compose down (clean) =="
down

echo "== pull images =="
docker pull --platform linux/amd64 apache/openmeetings:min-9.1.0 || true
docker pull --platform linux/amd64 eclipse-temurin:21-jre-noble || true
docker pull mariadb:10.11 || true

echo "== docker compose build =="
docker compose -p "${COMPOSE_PROJECT_NAME}" build --pull || true

echo "== docker compose up =="
up_ok=0
for attempt in $(seq 1 12); do
  if docker compose -p "${COMPOSE_PROJECT_NAME}" up -d --build; then
    up_ok=1
    break
  fi
  echo "IOC compose-up-retry attempt=${attempt}"
  sleep 90
  down
done
if [[ "${up_ok}" != 1 ]]; then
  fail_run "compose up failed"
fi

echo "== wait OpenMeetings HTTPS version (up to 10 min, qemu amd64 is slow) =="
ready=0
url="https://${OM_HOST}:${OM_PORT}/openmeetings/services/info/version"
for i in $(seq 1 120); do
  code="$(curl -skS -o /tmp/om-g1-version.txt -w '%{http_code}' --max-time 8 "${url}" || true)"
  if [[ "${code}" == "200" ]] && grep -qi '9.1' /tmp/om-g1-version.txt 2>/dev/null; then
    ready=1
    echo "IOC om-ready attempt=${i} http=${code}"
    break
  fi
  echo "IOC om-wait attempt=${i} http=${code}"
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
    echo "FAIL OPENMEETINGS-CALENDAR-SAVE-WITNESS poc exit=${rc}" >> poc-last-run.txt
  fi
  docker compose -p "${COMPOSE_PROJECT_NAME}" logs --tail=80 openmeetings db || true
fi

down
exit "${rc}"
