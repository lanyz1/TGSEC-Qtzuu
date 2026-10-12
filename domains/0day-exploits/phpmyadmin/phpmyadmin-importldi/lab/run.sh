#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-phpmyadmin-importldi}"
export PYTHONUNBUFFERED=1

LABEL="phpmyadmin-importldi"
WITNESS="PMA-IMPORTLDI-WITNESS"
READY_URL="http://127.0.0.1:19290/index.php?route=/"

down() {
  echo "== docker compose down -v =="
  docker compose -p "${COMPOSE_PROJECT_NAME}" down -v --remove-orphans || true
}

fail_setup() {
  local reason="$1"
  echo "FAIL ${LABEL} ${reason} ${WITNESS}" | tee poc-last-run.txt
  exit 1
}

trap down EXIT

echo "== docker compose down (clean) =="
down

echo "== docker pull mysql:8.0 phpmyadmin:5.2.3 =="
docker pull mysql:8.0 || fail_setup "mysql-image-pull-failed"
docker pull phpmyadmin:5.2.3 || fail_setup "pma-image-pull-failed"

echo "== docker compose up =="
up_ok=0
for attempt in $(seq 1 5); do
  if docker compose -p "${COMPOSE_PROJECT_NAME}" up -d; then
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

req = urllib.request.Request("http://127.0.0.1:19290/index.php?route=/", method="GET")
try:
    with urllib.request.urlopen(req, timeout=5) as resp:
        body = resp.read(64)
        if resp.status == 200 or body:
            raise SystemExit(0)
except urllib.error.HTTPError as exc:
    if exc.code in (200, 302, 401, 403):
        raise SystemExit(0)
    raise SystemExit(1)
except OSError:
    raise SystemExit(1)
raise SystemExit(1)
PY
  then
    ok=1
    echo "pma-ready attempt=${i}"
    break
  fi
  echo "pma-wait attempt=${i}"
  sleep 2
done
if [[ "${ok}" != 1 ]]; then
  echo "== compose logs (not ready) =="
  docker compose -p "${COMPOSE_PROJECT_NAME}" logs --no-color --tail=80 || true
  fail_setup "pma-not-ready"
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
