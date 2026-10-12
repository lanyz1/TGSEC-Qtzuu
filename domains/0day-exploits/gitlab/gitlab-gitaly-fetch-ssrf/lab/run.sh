#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-gitlab-gitaly-fetch-ssrf}"
export GITLAB_URL="${GITLAB_URL:-http://127.0.0.1:18410}"

mkdir -p logs
: > logs/catcher.log
: > logs/dns.log

down() {
  echo "== docker compose down -v =="
  docker compose -p "${COMPOSE_PROJECT_NAME}" down -v --remove-orphans || true
}

compose_up() {
  local attempt
  echo "== docker compose up --build =="
  for attempt in $(seq 1 25); do
    if docker compose -p "${COMPOSE_PROJECT_NAME}" up --build -d; then
      return 0
    fi
    echo "compose-up-retry attempt=${attempt}"
    sleep 60
    down
  done
  return 1
}

wait_gitlab() {
  local i code
  echo "== wait GitLab sign_in =="
  for i in $(seq 1 150); do
    code="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 8 \
      "${GITLAB_URL}/users/sign_in" || true)"
    if [[ "${code}" == "200" ]]; then
      echo "gitlab-ready attempt=${i} http=${code}"
      return 0
    fi
    echo "gitlab-wait attempt=${i} http=${code}"
    sleep 8
  done
  return 1
}

down

if ! compose_up; then
  echo "FAIL GITLAB-GITALY-FETCH-SSRF compose up failed" | tee poc-last-run.txt
  down
  exit 1
fi

if ! wait_gitlab; then
  echo "FAIL GITLAB-GITALY-FETCH-SSRF gitlab not ready" | tee poc-last-run.txt
  docker compose -p "${COMPOSE_PROJECT_NAME}" logs --tail=80 || true
  down
  exit 1
fi

echo "== poc.py =="
set +e
python3 ./poc.py | tee poc-last-run.txt
rc="${PIPESTATUS[0]}"
set -e
if [[ "${rc}" != 0 ]]; then
  if ! tail -n1 poc-last-run.txt 2>/dev/null | grep -qE '^(SUCCESS|FAIL) '; then
    echo "FAIL GITLAB-GITALY-FETCH-SSRF poc exit=${rc}" >> poc-last-run.txt
  fi
fi

down
exit "${rc}"
