#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-gitea-stargazers-hidden}"
BASE="${1:-http://127.0.0.1:18133}"
chmod +x poc.py

down() {
  echo "== docker compose down =="
  docker compose down -v || true
}

wait_ready() {
  local i code
  echo "== wait for Gitea =="
  for i in $(seq 1 60); do
    code="$(curl -s -o /tmp/gitea-stargazers-hidden-ver -w '%{http_code}' --max-time 5 "${BASE}/api/v1/version" || true)"
    if [[ "${code}" == "200" ]]; then
      echo "IOC gitea-up http=${code}"
      return 0
    fi
    echo "IOC wait i=${i} http=${code}"
    sleep 3
  done
  return 1
}

echo "== docker compose up (gitea/gitea:1.27.3, loopback :18133) =="
up_ok=0
for attempt in $(seq 1 8); do
  if docker compose up -d --build; then
    up_ok=1
    break
  fi
  echo "IOC compose-up-retry attempt=${attempt}"
  sleep 10
done
if [[ "${up_ok}" != 1 ]]; then
  echo "FAIL docker compose up" | tee poc-last-run.txt
  docker compose logs --tail=80 gitea || true
  down
  exit 1
fi

if ! wait_ready; then
  echo "FAIL Gitea did not become ready" | tee poc-last-run.txt
  docker compose logs --tail=80 gitea || true
  down
  exit 1
fi

echo "== poc.py =="
set +e
python3 poc.py "${BASE}" | tee poc-last-run.txt
rc=${PIPESTATUS[0]}
set -e
if [[ "${rc}" != 0 ]]; then
  echo "== gitea logs (tail) ==" | tee -a poc-last-run.txt
  docker compose logs --tail=80 gitea | tee -a poc-last-run.txt || true
fi
down
exit "${rc}"
