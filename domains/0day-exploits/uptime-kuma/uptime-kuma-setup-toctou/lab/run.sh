#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
export COMPOSE_PROJECT_NAME=uptime-kuma-setup-toctou
export LAB_SERVICE=kuma
BASE="${1:-http://127.0.0.1:18141}"
MAX_VOLUMES="${MAX_VOLUMES:-8}"
chmod +x poc.py

down() {
  echo "== compose down -v =="
  docker compose -p "$COMPOSE_PROJECT_NAME" down -v --remove-orphans >/dev/null 2>&1 || true
}

compose_up_retry() {
  local vol="$1"
  local attempt
  for attempt in $(seq 1 8); do
    if docker compose -p "$COMPOSE_PROJECT_NAME" up -d; then
      return 0
    fi
    echo "IOC compose-up-retry attempt=$attempt volume=$vol"
    sleep 5
  done
  return 1
}

wait_socketio() {
  local vol="$1"
  local i code
  for i in $(seq 1 60); do
    code="$(curl -s -o /tmp/uptime-kuma-setup-toctou-eio -w '%{http_code}' --max-time 5 \
      "$BASE/socket.io/?EIO=4&transport=polling" || true)"
    if [[ "$code" == "200" ]]; then
      echo "IOC kuma-up http=$code volume=$vol"
      return 0
    fi
    echo "IOC wait i=$i http=$code volume=$vol"
    sleep 2
  done
  return 1
}

trap down EXIT

if [[ ! -x .venv/bin/python ]]; then
  echo "== venv =="
  python3 -m venv .venv
  .venv/bin/pip install -q -r requirements.txt
fi

echo "== docker compose up (louislam/uptime-kuma:2.5.5, loopback :18141) =="
final_rc=1
for vol in $(seq 1 "$MAX_VOLUMES"); do
  echo "== volume attempt $vol/$MAX_VOLUMES =="
  docker compose -p "$COMPOSE_PROJECT_NAME" down -v --remove-orphans >/dev/null 2>&1 || true
  if ! compose_up_retry "$vol"; then
    echo "FAIL docker compose up volume=$vol" | tee poc-last-run.txt
    docker compose -p "$COMPOSE_PROJECT_NAME" logs --tail=80 kuma || true
    exit 1
  fi

  echo "== wait for socket.io =="
  if ! wait_socketio "$vol"; then
    echo "FAIL kuma did not become ready on $BASE volume=$vol" | tee poc-last-run.txt
    docker compose -p "$COMPOSE_PROJECT_NAME" logs --tail=80 kuma || true
    exit 1
  fi

  echo "== poc.py volume=$vol =="
  set +e
  .venv/bin/python poc.py "$BASE" | tee poc-last-run.txt
  rc=${PIPESTATUS[0]}
  set -e
  echo "IOC poc-exit rc=$rc volume=$vol"
  if [[ "$rc" == "0" ]]; then
    final_rc=0
    break
  fi
  if [[ "$rc" == "2" ]]; then
    echo "IOC race-miss volume=$vol (fresh volume next)"
    continue
  fi
  echo "== kuma logs (tail) ==" | tee -a poc-last-run.txt
  docker compose -p "$COMPOSE_PROJECT_NAME" logs --tail=80 kuma | tee -a poc-last-run.txt || true
  final_rc=1
  break
done

if [[ "$final_rc" != 0 ]]; then
  if ! grep -q '^FAIL uptime-kuma-setup-toctou' poc-last-run.txt 2>/dev/null; then
    echo "FAIL uptime-kuma-setup-toctou" | tee -a poc-last-run.txt
  fi
fi
exit "$final_rc"
