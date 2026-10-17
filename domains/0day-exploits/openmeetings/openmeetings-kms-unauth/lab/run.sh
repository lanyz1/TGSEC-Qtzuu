#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-om-g12-kms}"
export PYTHONUNBUFFERED=1
chmod +x poc.py

WITNESS="OPENMEETINGS-KMS-UNAUTH-WITNESS"
KMS_HOST="127.0.0.1"
KMS_PORT="18164"

down() {
  echo "== docker compose down -v =="
  docker compose -p "${COMPOSE_PROJECT_NAME}" --profile full --profile docs down -v --remove-orphans || true
}

fail_setup() {
  local reason="$1"
  echo "FAIL ${WITNESS} ${reason}" | tee poc-last-run.txt
  docker compose -p "${COMPOSE_PROJECT_NAME}" --profile full --profile docs logs --no-color --tail=80 || true
  down
  exit 1
}

wait_tcp() {
  python3 - "$KMS_HOST" "$KMS_PORT" <<'PY'
import socket, sys, time
host, port = sys.argv[1], int(sys.argv[2])
ok_streak = 0
for i in range(1, 13):
    try:
        s = socket.create_connection((host, port), timeout=3)
        s.close()
        ok_streak += 1
        print(f"IOC kms-tcp-ready attempt={i} streak={ok_streak} {host}:{port}", flush=True)
        if ok_streak >= 2:
            raise SystemExit(0)
        time.sleep(2)
    except OSError as exc:
        ok_streak = 0
        print(f"IOC kms-tcp-wait attempt={i} err={exc}", flush=True)
        time.sleep(15)
raise SystemExit(1)
PY
}

compose_up() {
  local profile="$1"
  local attempt
  echo "== docker compose up profile=${profile} =="
  for attempt in $(seq 1 12); do
    if COMPOSE_PROFILES="${profile}" docker compose -p "${COMPOSE_PROJECT_NAME}" up -d; then
      return 0
    fi
    echo "IOC compose-up-retry profile=${profile} attempt=${attempt}"
    sleep 15
    down
  done
  return 1
}

pull_one() {
  local image="$1"
  echo "== docker pull --platform linux/amd64 ${image} =="
  docker pull --platform linux/amd64 "${image}"
}

trap down EXIT

echo "== docker compose down (clean) =="
down

if ! pull_one "apache/openmeetings:9.1.0"; then
  fail_setup "image-pull-failed"
fi

profile="full"
if ! compose_up full; then
  fail_setup "compose-up-failed"
fi

if ! wait_tcp; then
  echo "== full image 8888 not stable; falling back to InstallMediaServer.md =="
  docker compose -p "${COMPOSE_PROJECT_NAME}" logs --no-color --tail=80 om || true
  down
  profile=""
fi

if [[ -z "${profile}" ]]; then
  if ! pull_one "kurento/kurento-media-server:7.3.0"; then
    echo "IOC kurento-7.3.0-missing; trying latest"
    if ! pull_one "kurento/kurento-media-server:latest"; then
      fail_setup "kms-image-pull-failed"
    fi
    sed -i.bak 's|kurento/kurento-media-server:7.3.0|kurento/kurento-media-server:latest|' docker-compose.yml || true
  fi
  pull_one "apache/openmeetings:min-9.1.0" || echo "IOC min-image-pull-skipped"
  if ! compose_up docs; then
    fail_setup "docs-compose-up-failed"
  fi
  profile="docs"
  if ! wait_tcp; then
    docker compose -p "${COMPOSE_PROJECT_NAME}" logs --no-color --tail=80 kms ommin || true
    fail_setup "8888-closed"
  fi
fi

echo "== poc.py profile=${profile} =="
set +e
python3 ./poc.py | tee poc-last-run.txt
rc=${PIPESTATUS[0]}
set -e

if [[ "${profile}" == "full" ]] && ! tail -n1 poc-last-run.txt 2>/dev/null | grep -q "^SUCCESS ${WITNESS}"; then
  echo "== full image JSON-RPC failed; falling back to InstallMediaServer.md =="
  docker compose -p "${COMPOSE_PROJECT_NAME}" logs --no-color --tail=80 om || true
  down
  if ! pull_one "kurento/kurento-media-server:7.3.0"; then
    fail_setup "kms-image-pull-failed"
  fi
  pull_one "apache/openmeetings:min-9.1.0" || echo "IOC min-image-pull-skipped"
  if ! compose_up docs; then
    fail_setup "docs-compose-up-failed"
  fi
  if ! wait_tcp; then
    docker compose -p "${COMPOSE_PROJECT_NAME}" logs --no-color --tail=80 kms ommin || true
    fail_setup "8888-closed"
  fi
  echo "== poc.py profile=docs =="
  set +e
  python3 ./poc.py | tee poc-last-run.txt
  rc=${PIPESTATUS[0]}
  set -e
fi

if ! tail -n1 poc-last-run.txt 2>/dev/null | grep -qE "^(SUCCESS|FAIL) ${WITNESS}"; then
  echo "FAIL ${WITNESS} poc-exit=${rc}" >> poc-last-run.txt
  rc=1
fi

exit "${rc}"
