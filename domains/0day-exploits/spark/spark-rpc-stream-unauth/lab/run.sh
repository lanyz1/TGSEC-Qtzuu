#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-spark-rpc-stream-unauth}"
export PYTHONUNBUFFERED=1

LABEL="SPARK-RPC-STREAM-UNAUTH"
WITNESS="SPARK-RPC-STREAM-UNAUTH-WITNESS"
READY_URL="http://127.0.0.1:18910/ping"

down() {
  echo "== docker compose down -v =="
  docker compose -p "${COMPOSE_PROJECT_NAME}" down -v --remove-orphans || true
}

fail_setup() {
  local reason="$1"
  printf '%s\n' "FAIL ${LABEL} ${reason} ${WITNESS}" | tee poc-last-run.txt
  exit 1
}

trap down EXIT

echo "== docker compose down (clean) =="
down

echo "== docker compose up --build =="
up_ok=0
for attempt in $(seq 1 5); do
  if docker compose -p "${COMPOSE_PROJECT_NAME}" up --build -d; then
    up_ok=1
    break
  fi
  echo "compose-up-retry attempt=${attempt}"
  sleep 8
  down
done
if [[ "${up_ok}" != 1 ]]; then
  fail_setup "compose-up-failed"
fi

echo "== wait ${READY_URL} =="
ok=0
for i in $(seq 1 90); do
  if python3 - <<'PY'
import urllib.error
import urllib.request

req = urllib.request.Request("http://127.0.0.1:18910/ping", method="GET")
try:
    with urllib.request.urlopen(req, timeout=3) as resp:
        body = resp.read().decode("utf-8", "replace")
        raise SystemExit(0 if resp.status == 200 and "pong" in body else 1)
except (urllib.error.URLError, TimeoutError, OSError):
    raise SystemExit(1)
PY
  then
    ok=1
    echo "vuln-ready attempt=${i}"
    break
  fi
  echo "vuln-wait attempt=${i}"
  sleep 1
done
if [[ "${ok}" != 1 ]]; then
  echo "== compose logs (not ready) =="
  docker compose -p "${COMPOSE_PROJECT_NAME}" logs --no-color --tail=120 || true
  fail_setup "vuln-not-ready"
fi

echo "== poc.py =="
set +e
python3 ./poc.py | tee poc-output.log
rc=${PIPESTATUS[0]}
set -e

verdict="$(grep -E '^(SUCCESS|FAIL) ' poc-output.log | tail -n1 || true)"
if [[ -z "${verdict}" ]]; then
  verdict="FAIL ${LABEL} poc-exit=${rc} ${WITNESS}"
  rc=1
fi
{
  printf '%s\n' "${verdict}"
  cat poc-output.log
} > poc-last-run.txt
rm -f poc-output.log

exit "${rc}"
