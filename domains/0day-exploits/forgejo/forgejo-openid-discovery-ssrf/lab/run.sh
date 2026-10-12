#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-forgejo-openid-discovery-ssrf}"
export FORGEJO_URL="${FORGEJO_URL:-http://127.0.0.1:19330}"
export PYTHONUNBUFFERED=1
chmod +x poc.py

LABEL="forgejo-openid-discovery-ssrf"
WITNESS="FORGEJO-OPENID-DISCOVERY-WITNESS"

down() {
  echo "== docker compose down -v =="
  docker compose -p "${COMPOSE_PROJECT_NAME}" down -v --remove-orphans || true
}

trap down EXIT

fail_setup() {
  local reason="$1"
  echo "FAIL ${LABEL} ${reason} ${WITNESS}" | tee poc-last-run.txt
  docker compose -p "${COMPOSE_PROJECT_NAME}" logs --no-color --tail=80 || true
  exit 1
}

echo "== docker compose down (clean) =="
down

echo "== docker compose up --build =="
up_ok=0
for attempt in $(seq 1 12); do
  if docker compose -p "${COMPOSE_PROJECT_NAME}" up --build -d; then
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

echo "== wait GET /user/login/openid on ${FORGEJO_URL} =="
ready=0
for i in $(seq 1 90); do
  code="$(curl -sS -o /tmp/forgejo-openid-login.html -w '%{http_code}' --max-time 8 \
    "${FORGEJO_URL}/user/login/openid" || true)"
  if [[ "${code}" == "200" ]] && grep -qi 'openid' /tmp/forgejo-openid-login.html 2>/dev/null; then
    ready=1
    echo "IOC forgejo-ready attempt=${i} http=${code}"
    break
  fi
  echo "IOC forgejo-wait attempt=${i} http=${code}"
  sleep 2
done
if [[ "${ready}" != 1 ]]; then
  fail_setup "forgejo-not-ready"
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
