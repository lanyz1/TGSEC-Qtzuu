#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-gitlab-webhook-0net-ssrf}"
GITLAB_URL="${GITLAB_URL:-http://127.0.0.1:18420}"
export COMPOSE_PROJECT_NAME GITLAB_URL

SIGNIN_HTML="/tmp/gitlab-webhook-0net-sign_in.html"
LAST_RUN="poc-last-run.txt"

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
    code="$(curl -sS -o "${SIGNIN_HTML}" -w '%{http_code}' --max-time 8 \
      -H 'Accept: text/html' "${GITLAB_URL}/users/sign_in" || true)"
    if [[ "${code}" == "200" ]] && grep -qi 'sign in' "${SIGNIN_HTML}" 2>/dev/null; then
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
  echo "FAIL GITLAB-WEBHOOK-0NET-SSRF compose up failed" | tee "${LAST_RUN}"
  down
  exit 1
fi

if ! wait_gitlab; then
  echo "FAIL GITLAB-WEBHOOK-0NET-SSRF gitlab not ready" | tee "${LAST_RUN}"
  docker compose -p "${COMPOSE_PROJECT_NAME}" logs --tail=80 || true
  down
  exit 1
fi

echo "== poc.py =="
set +e
python3 ./poc.py | tee "${LAST_RUN}"
rc="${PIPESTATUS[0]}"
set -e
if [[ "${rc}" != 0 ]]; then
  if ! tail -n1 "${LAST_RUN}" 2>/dev/null | grep -qE '^(SUCCESS|FAIL) '; then
    echo "FAIL GITLAB-WEBHOOK-0NET-SSRF poc exit=${rc}" >> "${LAST_RUN}"
  fi
fi

down
exit "${rc}"
