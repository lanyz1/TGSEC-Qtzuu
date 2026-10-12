#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-vaultwarden-ip-header-spoof}"
export VW_URL="${VW_URL:-http://127.0.0.1:18170}"
export VW_NONE_URL="${VW_NONE_URL:-http://127.0.0.1:18171}"
chmod +x ./poc.py

compose() {
  docker compose -p "${COMPOSE_PROJECT_NAME}" "$@"
}

down() {
  echo "== docker compose down -v =="
  compose down -v --remove-orphans || true
}

fail_run() {
  echo "FAIL VAULTWARDEN-IP-HEADER-SPOOF $*" | tee poc-last-run.txt
  compose logs --tail=80 vw vw-none || true
  down
  exit 1
}

compose_up() {
  local attempt
  echo "== docker compose up =="
  for attempt in $(seq 1 12); do
    if compose up -d; then
      return 0
    fi
    echo "IOC compose-up-retry attempt=${attempt}"
    sleep 30
    down
  done
  return 1
}

wait_ready() {
  local i alive alive_none
  echo "== wait /alive on both instances =="
  for i in $(seq 1 90); do
    alive="$(curl -sS -o /tmp/vw-ip-spoof-alive.txt -w '%{http_code}' --max-time 8 "${VW_URL}/alive" || true)"
    alive_none="$(curl -sS -o /tmp/vw-ip-spoof-alive-none.txt -w '%{http_code}' --max-time 8 "${VW_NONE_URL}/alive" || true)"
    if [[ "${alive}" == "200" && "${alive_none}" == "200" ]]; then
      echo "IOC vw-ready attempt=${i} alive=${alive} alive-none=${alive_none}"
      return 0
    fi
    echo "IOC vw-wait attempt=${i} alive=${alive} alive-none=${alive_none}"
    sleep 2
  done
  return 1
}

echo "== docker compose down (clean) =="
down

if ! compose_up; then
  fail_run "compose up failed"
fi

if ! wait_ready; then
  fail_run "instances not ready"
fi

echo "== poc.py =="
set +e
python3 ./poc.py | tee poc-last-run.txt
rc=${PIPESTATUS[0]}
set -e
if [[ "${rc}" != 0 ]]; then
  if ! grep -qE 'FAIL VAULTWARDEN-IP-HEADER-SPOOF|SUCCESS VAULTWARDEN-IP-HEADER-SPOOF' poc-last-run.txt 2>/dev/null; then
    echo "FAIL VAULTWARDEN-IP-HEADER-SPOOF poc exit=${rc}" >> poc-last-run.txt
  fi
fi

down
exit "${rc}"
