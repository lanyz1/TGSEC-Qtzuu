#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-nextcloud-calendar-sharee-publish}"
export NC_URL="${NC_URL:-http://127.0.0.1:18344}"
export NC_ADMIN_USER="${NC_ADMIN_USER:-admin}"
export NC_ADMIN_PASSWORD="${NC_ADMIN_PASSWORD:-LabAdmin35!}"
export NC_OWNER_USER="${NC_OWNER_USER:-owner}"
export NC_OWNER_PASSWORD="${NC_OWNER_PASSWORD:-LabOwner35!}"
export NC_SHAREE_USER="${NC_SHAREE_USER:-sharee}"
export NC_SHAREE_PASSWORD="${NC_SHAREE_PASSWORD:-LabSharee35!}"

LABEL="NEXTCLOUD-CAL-SHAREE-PUBLISH"
COMPOSE=(docker compose -p "${COMPOSE_PROJECT_NAME}")

fail_line() {
  echo "FAIL ${LABEL} ${1}"
}

down() {
  echo "== docker compose down -v =="
  "${COMPOSE[@]}" down -v --remove-orphans || true
}

occ() {
  "${COMPOSE[@]}" exec -T -u www-data nextcloud php occ "$@"
}

add_user() {
  local user="$1"
  local pass="$2"
  local display="$3"
  if occ user:info "${user}" >/dev/null 2>&1; then
    return 0
  fi
  "${COMPOSE[@]}" exec -T -u www-data -e NC_PASS="${pass}" nextcloud php occ \
    user:add --password-from-env --display-name="${display}" "${user}"
}

compose_up() {
  local attempt
  echo "== docker compose up (loopback :18344) =="
  for attempt in $(seq 1 8); do
    if "${COMPOSE[@]}" up -d; then
      return 0
    fi
    echo "IOC compose-up-retry attempt=${attempt}"
    sleep 12
  done
  return 1
}

wait_installed() {
  local i body
  echo "== wait for status.php installed=true =="
  for i in $(seq 1 120); do
    body="$(curl -sS --max-time 8 "${NC_URL}/status.php" || true)"
    echo "IOC wait i=${i} status=${body}"
    if echo "${body}" | grep -q '"installed":true'; then
      echo "IOC nextcloud-up installed=true"
      return 0
    fi
    sleep 5
  done
  return 1
}

wait_occ() {
  local attempt
  echo "== seed occ / DAV =="
  for attempt in $(seq 1 20); do
    if occ status; then
      return 0
    fi
    echo "IOC occ-wait attempt=${attempt}"
    sleep 5
  done
  return 1
}

seed() {
  local attempt limit_val
  occ app:enable dav || true
  occ app:enable calendar || true
  occ config:system:set overwrite.cli.url --value="${NC_URL}"
  occ config:system:set auth.bruteforce.protection.enabled --value=false --type=boolean || true
  for attempt in $(seq 1 10); do
    if add_user "${NC_OWNER_USER}" "${NC_OWNER_PASSWORD}" owner \
      && add_user "${NC_SHAREE_USER}" "${NC_SHAREE_PASSWORD}" sharee; then
      break
    fi
    echo "IOC user-add-retry attempt=${attempt}"
    sleep 4
  done
  occ user:info "${NC_OWNER_USER}" || true
  occ user:info "${NC_SHAREE_USER}" || true
  limit_val="$(occ config:app:get dav limitAddressBookAndCalendarSharingToOwner || true)"
  echo "IOC dav-limitAddressBookAndCalendarSharingToOwner=${limit_val:-unset-default-no}"
  if [[ "${limit_val}" == "yes" ]]; then
    fail_line "limitAddressBookAndCalendarSharingToOwner=yes" | tee poc-last-run.txt
    down
    exit 1
  fi
  occ dav:create-calendar "${NC_OWNER_USER}" labcal || true
  occ app:list | grep -Ei 'dav|calendar' || true
}

wait_owner_dav() {
  local i code
  echo "== wait owner CalDAV =="
  for i in $(seq 1 40); do
    code="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 15 \
      -u "${NC_OWNER_USER}:${NC_OWNER_PASSWORD}" \
      -X PROPFIND \
      -H 'Depth: 1' \
      -H 'Content-Type: application/xml' \
      "${NC_URL}/remote.php/dav/calendars/${NC_OWNER_USER}/" || true)"
    echo "IOC dav-wait i=${i} http=${code}"
    if [[ "${code}" == "207" || "${code}" == "200" ]]; then
      return 0
    fi
    sleep 3
  done
  return 1
}

chmod +x poc.py

echo "== docker compose down (clean) =="
"${COMPOSE[@]}" down -v --remove-orphans || true

if ! compose_up; then
  fail_line "docker compose up" | tee poc-last-run.txt
  "${COMPOSE[@]}" logs --tail=80 nextcloud || true
  down
  exit 1
fi

if ! wait_installed; then
  fail_line "status.php not installed" | tee poc-last-run.txt
  "${COMPOSE[@]}" logs --tail=80 nextcloud || true
  down
  exit 1
fi

if ! wait_occ; then
  fail_line "occ not ready" | tee poc-last-run.txt
  "${COMPOSE[@]}" logs --tail=80 nextcloud || true
  down
  exit 1
fi

seed

if ! wait_owner_dav; then
  fail_line "owner CalDAV not ready" | tee poc-last-run.txt
  "${COMPOSE[@]}" logs --tail=80 nextcloud || true
  down
  exit 1
fi

echo "== poc.py =="
set +e
python3 poc.py | tee poc-last-run.txt
rc=${PIPESTATUS[0]}
set -e
if [[ "${rc}" != 0 ]]; then
  echo "== nextcloud logs (tail) ==" | tee -a poc-last-run.txt
  "${COMPOSE[@]}" logs --tail=120 nextcloud | tee -a poc-last-run.txt || true
fi
down
exit "${rc}"
