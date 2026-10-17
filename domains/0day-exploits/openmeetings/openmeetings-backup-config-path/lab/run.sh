#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-om-g10-backup}"
export PYTHONUNBUFFERED=1
export OM_URL="${OM_URL:-https://127.0.0.1:18160}"
chmod +x poc.py entrypoint.sh

WITNESS="OPENMEETINGS-BACKUP-CONFIG-PATH-WITNESS"

down() {
  echo "== docker compose down -v =="
  docker compose -p "${COMPOSE_PROJECT_NAME}" down -v --remove-orphans || true
}

fail_setup() {
  local reason="$1"
  echo "FAIL ${WITNESS} ${reason}" | tee poc-last-run.txt
  docker compose -p "${COMPOSE_PROJECT_NAME}" logs --no-color --tail=160 openmeetings db || true
  down
  exit 1
}

trap down EXIT

echo "== docker compose down (clean) =="
down

if ! docker image inspect apache/openmeetings:min-9.1.0 >/dev/null 2>&1; then
  echo "== docker pull apache/openmeetings:min-9.1.0 =="
  docker pull --platform linux/amd64 apache/openmeetings:min-9.1.0 || fail_setup "image-pull-failed"
fi

echo "== docker compose build =="
build_ok=0
for attempt in $(seq 1 12); do
  if docker compose -p "${COMPOSE_PROJECT_NAME}" build; then
    build_ok=1
    break
  fi
  echo "IOC compose-build-retry attempt=${attempt}"
  sleep 20
done
if [[ "${build_ok}" != 1 ]]; then
  fail_setup "compose-build-failed"
fi

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

echo "== wait https://127.0.0.1:18160/openmeetings/services/info/version =="
ready=0
for i in $(seq 1 180); do
  code="$(curl -skS -o /tmp/om-g10-ready.html -w '%{http_code}' --max-time 8 \
    "https://127.0.0.1:18160/openmeetings/services/info/version" || true)"
  if [[ "${code}" == "200" ]]; then
    ready=1
    echo "IOC om-http-ready attempt=${i} http=${code}"
    break
  fi
  echo "IOC om-http-wait attempt=${i} http=${code}"
  sleep 5
done
if [[ "${ready}" != 1 ]]; then
  fail_setup "openmeetings-not-ready"
fi

echo "== wait REST login =="
login_ready=0
for i in $(seq 1 90); do
  code="$(curl -skS -o /tmp/om-g10-login.html -w '%{http_code}' --max-time 8 \
    -X POST "https://127.0.0.1:18160/openmeetings/services/user/login" \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    --data 'user=om_admin&pass=1Q2w3e4r5t%5Ey' || true)"
  if [[ "${code}" == "200" ]] && grep -qiE 'SUCCESS' /tmp/om-g10-login.html; then
    login_ready=1
    echo "IOC om-login-ready attempt=${i} http=${code}"
    break
  fi
  echo "IOC om-login-wait attempt=${i} http=${code}"
  sleep 4
done
if [[ "${login_ready}" != 1 ]]; then
  fail_setup "om-admin-login-failed"
fi

echo "== poc.py =="
set +e
python3 ./poc.py | tee poc-last-run.txt
rc=${PIPESTATUS[0]}
set -e

if ! tail -n1 poc-last-run.txt 2>/dev/null | grep -qE '^(SUCCESS|FAIL) '; then
  echo "FAIL ${WITNESS} poc-exit=${rc}" >> poc-last-run.txt
  rc=1
fi

if [[ "${rc}" != 0 ]]; then
  docker compose -p "${COMPOSE_PROJECT_NAME}" logs --no-color --tail=80 openmeetings db || true
fi

exit "${rc}"
