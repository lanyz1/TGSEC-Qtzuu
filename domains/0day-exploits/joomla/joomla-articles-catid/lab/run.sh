#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-joomla-articles-catid}"
export PYTHONUNBUFFERED=1
chmod +x poc.py

LABEL="joomla-articles-catid"
WITNESS="JOOMLA-ARTICLES-CATID-WITNESS"

down() {
  echo "== docker compose down -v =="
  docker compose -p "${COMPOSE_PROJECT_NAME}" down -v --remove-orphans || true
}

fail_setup() {
  local reason="$1"
  echo "FAIL ${LABEL} ${reason} ${WITNESS}" | tee poc-last-run.txt
  docker compose -p "${COMPOSE_PROJECT_NAME}" logs --no-color --tail=80 joomla db || true
  down
  exit 1
}

trap down EXIT

echo "== docker compose down (clean) =="
down

if ! docker image inspect joomla:6.1.3-php8.3-apache >/dev/null 2>&1; then
  echo "== docker pull joomla:6.1.3-php8.3-apache =="
  docker pull joomla:6.1.3-php8.3-apache || fail_setup "image-pull-failed"
fi

echo "== docker compose up =="
up_ok=0
for attempt in $(seq 1 8); do
  if docker compose -p "${COMPOSE_PROJECT_NAME}" up -d; then
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

echo "== wait http://127.0.0.1:19550/administrator/ =="
ready=0
for i in $(seq 1 90); do
  code="$(curl -sS -o /tmp/joomla-articles-catid-ready.html -w '%{http_code}' --max-time 8 \
    "http://127.0.0.1:19550/administrator/" || true)"
  if [[ "${code}" == "200" ]] && grep -q 'form-login\|mod-login-username' /tmp/joomla-articles-catid-ready.html; then
    ready=1
    echo "IOC joomla-ready attempt=${i} http=${code}"
    break
  fi
  echo "IOC joomla-wait attempt=${i} http=${code}"
  sleep 3
done
if [[ "${ready}" != 1 ]]; then
  fail_setup "joomla-not-ready"
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
