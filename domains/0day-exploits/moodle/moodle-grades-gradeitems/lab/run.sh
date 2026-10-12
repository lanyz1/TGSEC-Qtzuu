#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-moodle-grades-gradeitems}"
export PYTHONUNBUFFERED=1
chmod +x poc.py entrypoint.sh || true

LABEL="moodle-grades-gradeitems"
WITNESS="MOODLE-GRADES-GRADEITEMS-WITNESS"
PIN_TAG="v5.2.3"
PIN_SHA="344232c15336c71b80f9aca8359ce0e0a9f3d116"
MOODLE_URL="${MOODLE_URL:-http://127.0.0.1:19590}"
PIN_REL="../../vendors/moodle/src"

down() {
  echo "== docker compose down -v =="
  docker compose -p "${COMPOSE_PROJECT_NAME}" down -v --remove-orphans || true
}

fail_setup() {
  local reason="$1"
  echo "FAIL ${LABEL} ${reason} ${WITNESS}" | tee poc-last-run.txt
  docker compose -p "${COMPOSE_PROJECT_NAME}" logs --no-color --tail=120 moodle db || true
  down
  exit 1
}

prepare_src() {
  if [[ -f src/public/version.php ]] && grep -q "5.2.3 (Build: 20260914)" src/public/version.php; then
    echo "IOC src-ready path=src"
    return
  fi
  rm -rf src
  mkdir -p src
  if [[ -f "${PIN_REL}/public/version.php" ]]; then
    echo "== copy pin tree ${PIN_REL} =="
    tar -C "${PIN_REL}" --exclude .git -cf - . | tar -C src -xf -
    rm -f src/config.php
  else
    echo "== git clone --depth 1 --branch ${PIN_TAG} =="
    git clone --depth 1 --branch "${PIN_TAG}" https://github.com/moodle/moodle.git src
    local head
    head="$(git -C src rev-parse HEAD)"
    echo "IOC cloned-sha=${head}"
    if [[ "${head}" != "${PIN_SHA}"* && "${head}" != "${PIN_SHA}" ]]; then
      case "${head}" in
        "${PIN_SHA}"*) ;;
        *) echo "IOC sha-note expected-prefix=${PIN_SHA} got=${head}" ;;
      esac
    fi
  fi
  if ! grep -q "5.2.3 (Build: 20260914)" src/public/version.php; then
    fail_setup "pin-version-mismatch"
  fi
  if [[ ! -f src/public/cache/classes/config.php ]]; then
    fail_setup "pin-missing-cache-config"
  fi
  chmod -R a+rwX src || true
  echo "IOC src-ready pin=${PIN_TAG}"
}

trap down EXIT

echo "== docker compose down (clean) =="
down

prepare_src
rm -f src/config.php

echo "== docker compose up --build =="
up_ok=0
for attempt in $(seq 1 6); do
  if docker compose -p "${COMPOSE_PROJECT_NAME}" up --build -d; then
    up_ok=1
    break
  fi
  echo "IOC compose-up-retry attempt=${attempt}"
  sleep 15
  down
  prepare_src
done
if [[ "${up_ok}" != 1 ]]; then
  fail_setup "compose-up-failed"
fi

echo "== wait ${MOODLE_URL}/login/index.php =="
ready=0
for i in $(seq 1 180); do
  code="$(curl -sS -o /tmp/moodle-grades-gradeitems-ready.html -w '%{http_code}' --max-time 8 \
    "${MOODLE_URL}/login/index.php" || true)"
  if [[ "${code}" == "200" ]] && grep -Eq 'logintoken|name="username"' /tmp/moodle-grades-gradeitems-ready.html; then
    ready=1
    echo "IOC moodle-ready attempt=${i} http=${code}"
    break
  fi
  echo "IOC moodle-wait attempt=${i} http=${code}"
  sleep 3
done
if [[ "${ready}" != 1 ]]; then
  fail_setup "moodle-not-ready"
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
