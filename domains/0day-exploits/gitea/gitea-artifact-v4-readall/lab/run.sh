#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-gitea-artifact-v4-readall}"
BASE="${1:-http://127.0.0.1:18135}"
chmod +x poc.py

compose() {
  docker compose -p "${COMPOSE_PROJECT_NAME}" "$@"
}

down() {
  echo "== docker compose down =="
  compose down -v --remove-orphans || true
}

wait_gitea() {
  local ok=0 i code
  echo "== wait for Gitea =="
  for i in $(seq 1 60); do
    code="$(curl -s -o /tmp/gitea-art-v4-ver -w '%{http_code}' --max-time 5 "${BASE}/api/v1/version" || true)"
    if [[ "${code}" == "200" ]]; then
      echo "IOC gitea-up http=${code}"
      ok=1
      break
    fi
    echo "IOC wait-gitea i=${i} http=${code}"
    sleep 3
  done
  if [[ "${ok}" != 1 ]]; then
    echo "FAIL Gitea did not become ready on ${BASE}" | tee poc-last-run.txt
    compose logs --tail=80 gitea || true
    exit 1
  fi
}

wait_runner() {
  local ok=0 i logs
  echo "== wait for runner =="
  for i in $(seq 1 40); do
    logs="$(compose logs runner 2>/dev/null || true)"
    if echo "${logs}" | grep -qiE 'runner[^\n]*(registered|ready)|listening for jobs|Start running|daemon'; then
      echo "IOC runner-up i=${i}"
      ok=1
      break
    fi
    echo "IOC wait-runner i=${i}"
    sleep 3
  done
  if [[ "${ok}" != 1 ]]; then
    echo "FAIL GITEA-ARTIFACT-V4-READALL no job token without runner" | tee poc-last-run.txt
    compose logs --tail=80 runner || true
    compose logs --tail=40 gitea || true
    exit 1
  fi
}

seed_admin() {
  echo "== seed admin =="
  compose exec -T -u git gitea gitea admin user create \
    --admin \
    --username labadmin \
    --password 'LabPass123!' \
    --email labadmin@localhost.invalid \
    --must-change-password=false >/dev/null 2>&1 || true
}

seed_hold_workflow() {
  local wf code repo_name
  echo "== seed repo + hold workflow =="
  wf="$(python3 - <<'PY'
import base64

src = """name: hold
on:
  push:
jobs:
  hold:
    runs-on: ubuntu-latest
    steps:
      - name: hold
        run: sleep 1800
"""
print(base64.b64encode(src.encode()).decode())
PY
)"

  curl -sS -u 'labadmin:LabPass123!' -H 'Content-Type: application/json' \
    -d '{"name":"hold-job","auto_init":true,"default_branch":"main","private":false}' \
    "${BASE}/api/v1/user/repos" >/tmp/gitea-art-v4-repo.json || true
  repo_name="$(python3 - <<'PY'
import json
from pathlib import Path

path = Path("/tmp/gitea-art-v4-repo.json")
try:
    print(json.loads(path.read_text(encoding="utf-8")).get("full_name", "err"))
except (OSError, json.JSONDecodeError):
    print("unknown")
PY
)"
  echo "IOC repo-create ${repo_name}"

  code="$(curl -sS -o /tmp/gitea-art-v4-wf -w '%{http_code}' -u 'labadmin:LabPass123!' \
    -H 'Content-Type: application/json' \
    -X POST \
    -d "{\"message\":\"add hold workflow\",\"content\":\"${wf}\"}" \
    "${BASE}/api/v1/repos/labadmin/hold-job/contents/.gitea%2Fworkflows%2Fhold.yml" || true)"
  echo "IOC workflow-create http=${code} snippet=$(head -c 160 /tmp/gitea-art-v4-wf 2>/dev/null || true)"

  if [[ "${code}" != "201" && "${code}" != "200" ]]; then
    echo "IOC workflow-create-not-201, continuing"
  fi
}

trap down EXIT

echo "== docker compose down leftover =="
compose down -v --remove-orphans || true

echo "== docker compose up (gitea 1.27.3 + act_runner host, loopback :18135) =="
up_ok=0
for attempt in $(seq 1 8); do
  if compose up -d --build; then
    up_ok=1
    break
  fi
  echo "IOC compose-up-retry attempt=${attempt}"
  sleep 8
done
if [[ "${up_ok}" != 1 ]]; then
  echo "FAIL docker compose up" | tee poc-last-run.txt
  compose logs --tail=80 || true
  exit 1
fi

wait_gitea
seed_admin
wait_runner
seed_hold_workflow

echo "== poc.py =="
set +e
python3 poc.py "${BASE}" | tee poc-last-run.txt
rc=${PIPESTATUS[0]}
set -e
if [[ "${rc}" != 0 ]]; then
  echo "== gitea/runner logs (tail) ==" | tee -a poc-last-run.txt
  compose logs --tail=80 gitea | tee -a poc-last-run.txt || true
  compose logs --tail=80 runner | tee -a poc-last-run.txt || true
fi
exit "${rc}"
