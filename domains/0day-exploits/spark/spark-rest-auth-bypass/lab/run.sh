#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-spark-rest-auth-bypass}"
export PYTHONUNBUFFERED=1
chmod +x poc.py start-master.sh start-worker.sh

down() {
  echo "== docker compose down -v =="
  docker compose -p "${COMPOSE_PROJECT_NAME}" down -v --remove-orphans || true
}

fail_run() {
  echo "FAIL SPARK-REST-AUTH-BYPASS $* SPARK-REST-AUTH-BYPASS-WITNESS" | tee poc-last-run.txt
  docker compose -p "${COMPOSE_PROJECT_NAME}" logs --tail=80 || true
  down
  exit 1
}

echo "== docker compose down (clean) =="
down

mkdir -p oracle
chmod 0777 oracle
rm -f oracle/SPARK-REST-AUTH-BYPASS-WITNESS

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
  fail_run "compose-up-failed"
fi

echo "== wait REST /v1/submissions/readyz =="
ready=0
for i in $(seq 1 90); do
  code="$(curl -sS -o /tmp/spark-rest-auth-bypass-readyz.txt -w '%{http_code}' --max-time 3 \
    http://127.0.0.1:18900/v1/submissions/readyz || true)"
  if [[ "${code}" == "200" ]]; then
    ready=1
    echo "rest-ready attempt=${i} readyz=${code}"
    break
  fi
  echo "rest-wait attempt=${i} readyz=${code}"
  sleep 2
done
if [[ "${ready}" != 1 ]]; then
  fail_run "rest-not-ready"
fi

echo "== wait worker registered =="
worker_ok=0
for i in $(seq 1 60); do
  if docker compose -p "${COMPOSE_PROJECT_NAME}" logs worker 2>/dev/null \
    | grep -qi 'registered with master'; then
    worker_ok=1
    echo "worker-ready attempt=${i}"
    break
  fi
  echo "worker-wait attempt=${i}"
  sleep 2
done
if [[ "${worker_ok}" != 1 ]]; then
  fail_run "worker-not-registered"
fi

echo "== poc.py =="
set +e
python3 ./poc.py | tee poc-last-run.txt
rc=${PIPESTATUS[0]}
set -e

if ! head -n1 poc-last-run.txt 2>/dev/null | grep -qE '^(SUCCESS|FAIL) '; then
  echo "FAIL SPARK-REST-AUTH-BYPASS poc-exit=${rc} SPARK-REST-AUTH-BYPASS-WITNESS" | tee poc-last-run.txt
  rc=1
fi

down
exit "${rc}"
