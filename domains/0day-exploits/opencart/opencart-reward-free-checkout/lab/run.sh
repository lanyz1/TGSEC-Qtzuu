#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-opencart-reward-free-checkout}"
export PYTHONUNBUFFERED=1

BASE="${1:-http://127.0.0.1:18108}"
POC="./poc.py"

if [[ ! -f www/index.php ]]; then
  echo "Place OpenCart 4.1.0.4 upload/ at ./www (https://github.com/opencart/opencart tag 4.1.0.4)"
  exit 1
fi
if [[ ! -f "${POC}" ]]; then
  echo "FAIL no poc.py"
  exit 1
fi
chmod +x "${POC}" setup-opencart.sh

down() {
  echo "== docker compose down =="
  docker compose down --remove-orphans || true
}

wait_ready() {
  local i code body
  body="$(mktemp)"
  echo "== wait for catalog =="
  for i in $(seq 1 90); do
    code="$(curl -s -o "${body}" -w '%{http_code}' --max-time 8 "${BASE}/" || true)"
    if [[ "${code}" == "200" ]] && grep -qiE 'opencart|common/home|featured|Your Store' "${body}" 2>/dev/null; then
      rm -f "${body}"
      echo "IOC opencart-up http=${code}"
      return 0
    fi
    echo "IOC wait i=${i} http=${code}"
    sleep 5
  done
  rm -f "${body}"
  echo "FAIL OpenCart did not become ready on ${BASE}"
  docker compose logs --tail=80 opencart || true
  return 1
}

echo "== docker compose up (OpenCart 4.1.0.4, loopback) =="
docker compose up -d --build

if ! wait_ready; then
  exit 1
fi

echo "== poc.py =="
python3 "${POC}" "${BASE}"
