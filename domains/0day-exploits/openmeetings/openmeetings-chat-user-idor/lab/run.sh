#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-om-g2-chat}"
export PYTHONUNBUFFERED=1
chmod +x poc.py entrypoint.sh

WITNESS="OPENMEETINGS-CHAT-IDOR-WITNESS"
HEALTH_URL="https://127.0.0.1:18151/openmeetings/services/info/version"

down() {
  echo "== docker compose down -v =="
  docker compose -p "${COMPOSE_PROJECT_NAME}" down -v --remove-orphans || true
}

fail_setup() {
  local reason="$1"
  echo "FAIL ${WITNESS} ${reason}" | tee poc-last-run.txt
  docker compose -p "${COMPOSE_PROJECT_NAME}" logs --no-color --tail=120 openmeetings mysql || true
  down
  exit 1
}

trap down EXIT

already_ready=0
body="$(curl -ksS --max-time 8 "${HEALTH_URL}" || true)"
if echo "${body}" | grep -q '9.1.0'; then
  already_ready=1
  echo "IOC reuse-stack version ${body}" | head -c 400
  echo
fi

if [[ "${already_ready}" != 1 ]]; then
  echo "== docker compose down (clean) =="
  down

  echo "== docker compose build =="
  if ! docker compose -p "${COMPOSE_PROJECT_NAME}" build; then
    fail_setup "image-build-failed"
  fi

  echo "== docker compose up =="
  up_ok=0
  for attempt in $(seq 1 12); do
    if docker compose -p "${COMPOSE_PROJECT_NAME}" up -d; then
      up_ok=1
      break
    fi
    echo "IOC compose-up-retry attempt=${attempt}"
    sleep 90
    down
  done
  if [[ "${up_ok}" != 1 ]]; then
    fail_setup "compose-up-failed"
  fi

  echo "== wait ${HEALTH_URL} =="
  ready=0
  for i in $(seq 1 144); do
    body="$(curl -ksS --max-time 8 "${HEALTH_URL}" || true)"
    if echo "${body}" | grep -qiE '9\.1\.0|version'; then
      ready=1
      echo "IOC om-ready attempt=${i}"
      echo "IOC version ${body}" | head -c 400
      echo
      break
    fi
    echo "IOC om-wait attempt=${i}"
    sleep 5
  done
  if [[ "${ready}" != 1 ]]; then
    fail_setup "om-not-ready"
  fi
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

exit "${rc}"
