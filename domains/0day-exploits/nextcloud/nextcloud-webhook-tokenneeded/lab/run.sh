#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-nextcloud-webhook-tokenneeded}"
export NC_URL="${NC_URL:-http://127.0.0.1:18320}"
export HOOK_URL="${HOOK_URL:-http://127.0.0.1:18321}"
export NC_ADMIN_USER="${NC_ADMIN_USER:-admin}"
export NC_ADMIN_PASSWORD="${NC_ADMIN_PASSWORD:-LabAdmin35!}"
export NC_HOOKER_USER="${NC_HOOKER_USER:-hooker}"
export NC_HOOKER_PASSWORD="${NC_HOOKER_PASSWORD:-LabHooker35!}"
export PYTHONUNBUFFERED=1

LABEL="NEXTCLOUD-WEBHOOK-TOKENNEEDED"
WITNESS="NEXTCLOUD-WEBHOOK-TOKENNEEDED-WITNESS"

chmod +x poc.py

occ() {
  docker compose exec -T -u www-data -e NC_PASS="${NC_HOOKER_PASSWORD}" nextcloud php occ "$@"
}

down() {
  echo "== docker compose down -v =="
  docker compose down -v --remove-orphans || true
}

compose_up() {
  echo "== docker compose up --build (loopback :18320/:18321) =="
  local attempt
  for attempt in $(seq 1 8); do
    if docker compose up -d --build; then
      return 0
    fi
    echo "IOC compose-up-retry attempt=${attempt}"
    sleep 12
  done
  echo "FAIL ${LABEL} docker compose up" | tee poc-last-run.txt
  docker compose logs --tail=80 nextcloud hook || true
  down
  exit 1
}

wait_installed() {
  echo "== wait for status.php installed=true =="
  local i body
  for i in $(seq 1 120); do
    body="$(curl -sS --max-time 8 "${NC_URL}/status.php" || true)"
    echo "IOC wait i=${i} status=${body}"
    if echo "${body}" | grep -q '"installed":true'; then
      echo "IOC nextcloud-up installed=true"
      return 0
    fi
    sleep 5
  done
  echo "FAIL ${LABEL} status.php not installed" | tee poc-last-run.txt
  docker compose logs --tail=80 nextcloud || true
  down
  exit 1
}

wait_occ() {
  echo "== seed occ / DAV =="
  local attempt
  for attempt in $(seq 1 20); do
    if occ status; then
      return 0
    fi
    echo "IOC occ-wait attempt=${attempt}"
    sleep 5
  done
  echo "FAIL ${LABEL} occ not ready" | tee poc-last-run.txt
  docker compose logs --tail=80 nextcloud || true
  down
  exit 1
}

seed() {
  occ app:enable webhook_listeners || true
  occ config:system:set allow_local_remote_servers --value=true --type=boolean
  occ config:system:set overwrite.cli.url --value="${NC_URL}"
  occ config:system:set auth.bruteforce.protection.enabled --value=false --type=boolean || true
  occ group:add webhookers || true
  occ user:add --password-from-env --display-name=hooker -g webhookers "${NC_HOOKER_USER}" || true
  occ group:adduser webhookers "${NC_HOOKER_USER}" || true
  occ admin-delegation:add 'OCA\WebhookListeners\Settings\Admin' webhookers || true
  occ user:info "${NC_HOOKER_USER}" || true
  occ app:list | grep -i webhook || true
}

plant_witness() {
  echo "== plant admin witness DAV file =="
  local i code
  for i in $(seq 1 30); do
    code="$(curl -sS -o /tmp/nc-webhook-tokenneeded-plant -w '%{http_code}' --max-time 20 \
      -u "${NC_ADMIN_USER}:${NC_ADMIN_PASSWORD}" \
      -H 'Content-Type: text/plain' \
      -X PUT \
      --data-binary "${WITNESS}" \
      "${NC_URL}/remote.php/dav/files/${NC_ADMIN_USER}/${WITNESS}.txt" || true)"
    echo "IOC plant i=${i} http=${code}"
    if [[ "${code}" == "201" || "${code}" == "204" || "${code}" == "200" ]]; then
      return 0
    fi
    sleep 3
  done
  echo "FAIL ${LABEL} plant witness DAV" | tee poc-last-run.txt
  docker compose logs --tail=80 nextcloud || true
  down
  exit 1
}

echo "== docker compose down (clean) =="
docker compose down -v --remove-orphans || true

compose_up
wait_installed
wait_occ
seed
plant_witness

echo "== poc.py =="
set +e
python3 poc.py | tee poc-last-run.txt
rc="${PIPESTATUS[0]}"
set -e
if [[ "${rc}" != 0 ]]; then
  echo "== nextcloud/hook logs (tail) ==" | tee -a poc-last-run.txt
  docker compose logs --tail=120 nextcloud hook | tee -a poc-last-run.txt || true
  echo "== occ webhook_listeners:list ==" | tee -a poc-last-run.txt
  occ webhook_listeners:list | tee -a poc-last-run.txt || true
fi
down
exit "${rc}"
