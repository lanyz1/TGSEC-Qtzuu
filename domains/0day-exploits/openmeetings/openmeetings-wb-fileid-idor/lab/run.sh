#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-om-g5-wb}"
export PYTHONUNBUFFERED=1
export OM_BASE="${OM_BASE:-https://127.0.0.1:18154/openmeetings}"
chmod +x poc.py entrypoint.sh

WITNESS="OPENMEETINGS-WB-FILEID-WITNESS"

down() {
  echo "== docker compose down -v =="
  docker compose -p "${COMPOSE_PROJECT_NAME}" down -v --remove-orphans || true
}

fail_run() {
  echo "FAIL ${WITNESS} $*" | tee poc-last-run.txt
  docker compose -p "${COMPOSE_PROJECT_NAME}" logs --no-color --tail=120 openmeetings || true
  down
  exit 1
}

wait_health() {
  local ready=0
  local i
  for i in $(seq 1 180); do
    if python3 - <<'PY'
import ssl, urllib.request
ctx = ssl._create_unverified_context()
url = "https://127.0.0.1:18154/openmeetings/services/info/health"
try:
    with urllib.request.urlopen(url, context=ctx, timeout=8) as r:
        body = r.read().decode("utf-8", "replace")
        print(body[:300])
        raise SystemExit(0 if ("true" in body.lower() or "inited" in body.lower() or "dbOk" in body.lower()) else 1)
except Exception as e:
    print("wait-err", type(e).__name__, e)
    raise SystemExit(1)
PY
    then
      ready=1
      echo "lab-ready attempt=${i}"
      break
    fi
    echo "lab-wait attempt=${i}"
    sleep 5
  done
  [[ "${ready}" == 1 ]]
}

compose_up() {
  local img="$1"
  local build_flag="$2"
  shift 2
  export OM_IMAGE="${img}"
  echo "== compose up image=${img} build=${build_flag} files=$* =="
  local up_ok=0
  local attempt
  for attempt in $(seq 1 12); do
    if docker compose -p "${COMPOSE_PROJECT_NAME}" "$@" up -d ${build_flag}; then
      up_ok=1
      break
    fi
    echo "compose-up-retry attempt=${attempt} image=${img}"
    sleep 8
    down
  done
  [[ "${up_ok}" == 1 ]]
}

echo "== docker compose down (clean) =="
down

IMAGE_MIN="om-g5-wb:min-9.1.0-jre"
IMAGE_FULL="apache/openmeetings:9.1.0"
USING="${IMAGE_MIN}"

if ! compose_up "${USING}" --build; then
  echo "== min build/up failed, switching to full =="
  down
  USING="${IMAGE_FULL}"
  if ! compose_up "${USING}" --no-build -f docker-compose.yml -f docker-compose.full.yml; then
    fail_run "compose-up-failed ${USING}"
  fi
fi

if ! wait_health; then
  echo "== min image not healthy, switching to full =="
  docker compose -p "${COMPOSE_PROJECT_NAME}" logs --no-color --tail=80 openmeetings || true
  down
  USING="${IMAGE_FULL}"
  if ! compose_up "${USING}" --no-build -f docker-compose.yml -f docker-compose.full.yml; then
    fail_run "compose-up-failed ${USING}"
  fi
  if ! wait_health; then
    echo "== compose logs (not ready) =="
    docker compose -p "${COMPOSE_PROJECT_NAME}" logs --no-color --tail=120 openmeetings || true
    fail_run "lab-not-ready ${USING}"
  fi
fi
echo "IOC image=${USING}"

echo "== poc.py =="
set +e
python3 ./poc.py | tee poc-last-run.txt
rc=${PIPESTATUS[0]}
set -e

if ! tail -n1 poc-last-run.txt 2>/dev/null | grep -qE '^(SUCCESS|FAIL) '; then
  echo "FAIL ${WITNESS} poc-exit=${rc}" >> poc-last-run.txt
  rc=1
fi

down
exit "${rc}"
