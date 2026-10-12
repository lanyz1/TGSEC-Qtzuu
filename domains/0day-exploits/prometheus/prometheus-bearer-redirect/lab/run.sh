#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-prometheus-bearer-redirect}"
export PYTHONUNBUFFERED=1
export PROM_URL="${PROM_URL:-http://127.0.0.1:19380}"
export ORACLE_URL="${ORACLE_URL:-http://127.0.0.1:19381}"

LABEL="prometheus-bearer-redirect"
WITNESS="PROMETHEUS-BEARER-REDIRECT-WITNESS"

down() {
  echo "== docker compose down -v =="
  docker compose -p "${COMPOSE_PROJECT_NAME}" down -v --remove-orphans || true
  rm -f gcp-sa.json
}

trap down EXIT

fail_setup() {
  local reason="$1"
  echo "FAIL ${LABEL} ${reason} ${WITNESS}" | tee poc-last-run.txt
  docker compose -p "${COMPOSE_PROJECT_NAME}" logs --no-color --tail=80 || true
  exit 1
}

echo "== docker compose down (clean) =="
down
trap down EXIT

echo "== generate google_iam credentials JSON =="
python3 - <<'PY'
import json
import subprocess
from pathlib import Path

pem = subprocess.check_output(["openssl", "genrsa", "2048"], stderr=subprocess.DEVNULL).decode("utf-8")
doc = {
    "type": "service_account",
    "project_id": "lab-project",
    "private_key_id": "lab-key",
    "private_key": pem,
    "client_email": "prometheus-lab@lab-project.iam.gserviceaccount.com",
    "client_id": "100000000000000000001",
    "auth_uri": "http://hop:8080/auth",
    "token_uri": "http://hop:8080/token",
}
Path("gcp-sa.json").write_text(json.dumps(doc), encoding="utf-8")
Path("gcp-sa.json").chmod(0o644)
print("IOC wrote gcp-sa.json")
PY

chmod +x poc.py

echo "== docker compose up =="
up_ok=0
for attempt in $(seq 1 8); do
  if docker compose -p "${COMPOSE_PROJECT_NAME}" up -d; then
    up_ok=1
    break
  fi
  echo "IOC compose-up-retry attempt=${attempt}"
  sleep 8
  docker compose -p "${COMPOSE_PROJECT_NAME}" down -v --remove-orphans || true
done
if [[ "${up_ok}" != 1 ]]; then
  fail_setup "compose-up-failed"
fi

echo "== wait prometheus 127.0.0.1:19380/-/ready and oracle /health =="
ready=0
for i in $(seq 1 90); do
  prom="$(curl -sS -o /tmp/prom-bearer-ready.txt -w '%{http_code}' --max-time 4 "${PROM_URL}/-/ready" || true)"
  oracle="$(curl -sS -o /tmp/prom-bearer-oracle.txt -w '%{http_code}' --max-time 4 "${ORACLE_URL}/health" || true)"
  if [[ "${prom}" == "200" && "${oracle}" == "200" ]]; then
    ready=1
    echo "IOC ready attempt=${i} prom=${prom} oracle=${oracle}"
    break
  fi
  echo "IOC wait attempt=${i} prom=${prom} oracle=${oracle}"
  sleep 2
done
if [[ "${ready}" != 1 ]]; then
  docker compose -p "${COMPOSE_PROJECT_NAME}" logs --no-color --tail=120 || true
  fail_setup "not-ready"
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
