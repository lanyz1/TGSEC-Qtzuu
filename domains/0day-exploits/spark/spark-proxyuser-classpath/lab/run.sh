#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-spark-proxyuser-classpath}"
export PYTHONUNBUFFERED=1

LABEL="SPARK-PROXYUSER-CLASSPATH"
WITNESS="SPARK-PROXYUSER-CLASSPATH-WITNESS"

down() {
  echo "== docker compose down -v =="
  docker compose -p "${COMPOSE_PROJECT_NAME}" down -v --remove-orphans || true
}

fail_setup() {
  local reason="$1"
  echo "FAIL ${LABEL} ${reason} ${WITNESS}" | tee poc-last-run.txt
  down
  exit 1
}

echo "== docker compose down (clean) =="
down

mkdir -p oracle
rm -f oracle/SPARK-PROXYUSER-CLASSPATH-WITNESS oracle/result.txt \
  oracle/control.txt oracle/closed-extra.txt oracle/flag-flip.txt \
  oracle/*-submit.txt oracle/*-child.txt

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

echo "== wait http://127.0.0.1:18950/health =="
ok=0
for i in $(seq 1 90); do
  if python3 - <<'PY'
import urllib.error
import urllib.request

req = urllib.request.Request("http://127.0.0.1:18950/health", method="GET")
try:
    with urllib.request.urlopen(req, timeout=3) as resp:
        body = resp.read().decode("utf-8", "replace")
        raise SystemExit(0 if resp.status == 200 and body.strip() == "ok" else 1)
except (urllib.error.URLError, TimeoutError, OSError):
    raise SystemExit(1)
PY
  then
    ok=1
    echo "lab-ready attempt=${i}"
    break
  fi
  echo "lab-wait attempt=${i}"
  sleep 1
done
if [[ "${ok}" != 1 ]]; then
  echo "== compose logs (not ready) =="
  docker compose -p "${COMPOSE_PROJECT_NAME}" logs --no-color --tail=80 || true
  fail_setup "lab-not-ready"
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

down
exit "${rc}"
