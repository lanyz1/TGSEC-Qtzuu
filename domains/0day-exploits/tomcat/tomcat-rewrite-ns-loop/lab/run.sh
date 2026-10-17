#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-tomcat-rewrite-ns-loop}"
export PYTHONUNBUFFERED=1

LABEL="TOMCAT-REWRITE-NS-LOOP"
WITNESS="TOMCAT-REWRITE-NS-LOOP-WITNESS"
BASE_IMAGE="eclipse-temurin:17-jre-jammy"
READY_URL="http://127.0.0.1:18910/"

down() {
  echo "== docker compose down -v =="
  docker compose -p "${COMPOSE_PROJECT_NAME}" down -v --remove-orphans || true
}

fail_setup() {
  local reason="$1"
  echo "FAIL ${LABEL} ${reason} ${WITNESS}" | tee poc-last-run.txt
  docker compose -p "${COMPOSE_PROJECT_NAME}" logs --no-color --tail=120 || true
  exit 1
}

trap down EXIT

echo "== docker compose down (clean) =="
down

if ! docker image inspect "${BASE_IMAGE}" >/dev/null 2>&1; then
  echo "== docker pull ${BASE_IMAGE} =="
  docker pull "${BASE_IMAGE}" || fail_setup "base-image-pull-failed"
fi

if docker image inspect tomcat:11.0.27-jre17 >/dev/null 2>&1; then
  echo "== local tomcat:11.0.27-jre17 present (lab still builds pinned 11.0.27 tarball) =="
fi

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

req = urllib.request.Request("http://127.0.0.1:18910/", method="GET")
try:
    with urllib.request.urlopen(req, timeout=3) as resp:
        raise SystemExit(0 if resp.status in (200, 404) else 1)
except urllib.error.HTTPError as exc:
    raise SystemExit(0 if exc.code in (200, 404) else 1)
except (urllib.error.URLError, TimeoutError, OSError):
    raise SystemExit(1)
PY
  then
    ok=1
    echo "tomcat-ready attempt=${i}"
    break
  fi
  echo "tomcat-wait attempt=${i}"
  sleep 2
done
if [[ "${ok}" != 1 ]]; then
  echo "== compose logs (not ready) =="
  docker compose -p "${COMPOSE_PROJECT_NAME}" logs --no-color --tail=120 || true
  fail_setup "tomcat-not-ready"
fi

echo "== catalina version =="
docker compose -p "${COMPOSE_PROJECT_NAME}" exec -T tomcat \
  bash -lc "grep 'Apache Tomcat Version' /usr/local/tomcat/RELEASE-NOTES | head -1" \
  || fail_setup "version-check-failed"

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
