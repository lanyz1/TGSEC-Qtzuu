#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-moodle-grades-feedback-idor}"
export PYTHONUNBUFFERED=1
chmod +x poc.py

LABEL="moodle-grades-feedback-idor"
WITNESS="MOODLE-GRADES-FEEDBACK-IDOR-WITNESS"
MOODLE_URL="${MOODLE_URL:-http://127.0.0.1:19580}"

down() {
  echo "== docker compose down -v =="
  docker compose -p "${COMPOSE_PROJECT_NAME}" down -v --remove-orphans || true
}

fail_setup() {
  local reason="$1"
  echo "FAIL ${LABEL} ${reason} ${WITNESS}" | tee poc-last-run.txt
  docker compose -p "${COMPOSE_PROJECT_NAME}" logs --no-color --tail=80 moodle db || true
  exit 1
}

trap down EXIT

echo "== docker compose down (clean) =="
down
trap down EXIT

echo "== docker compose up --build =="
up_ok=0
for attempt in $(seq 1 8); do
  if docker compose -p "${COMPOSE_PROJECT_NAME}" up --build -d; then
    up_ok=1
    break
  fi
  echo "IOC compose-up-retry attempt=${attempt}"
  sleep 20
  down
done
if [[ "${up_ok}" != 1 ]]; then
  fail_setup "compose-up-failed"
fi

echo "== wait php server (pin copy may take a few minutes) =="
ready=0
for i in $(seq 1 180); do
  code="$(curl -sS -o /tmp/moodle-grades-feedback-idor-ready.html -w '%{http_code}' --max-time 8 \
    "${MOODLE_URL}/login/index.php" || true)"
  if [[ "${code}" == "200" ]] || [[ "${code}" == "303" ]] || [[ "${code}" == "302" ]]; then
    ready=1
    echo "IOC moodle-http attempt=${i} http=${code}"
    break
  fi
  echo "IOC moodle-wait attempt=${i} http=${code}"
  sleep 3
done
if [[ "${ready}" != 1 ]]; then
  fail_setup "moodle-http-not-ready"
fi

echo "== install database if empty =="
tables="$(docker compose -p "${COMPOSE_PROJECT_NAME}" exec -T db \
  mariadb -umoodle -pLabDbPassw0rd! -N -B -e "SHOW TABLES FROM moodle LIKE 'mdl_user'" || true)"
if [[ "${tables}" != *mdl_user* ]]; then
  echo "== php admin/cli/install_database.php =="
  if ! docker compose -p "${COMPOSE_PROJECT_NAME}" exec -T moodle \
    php /var/www/html/admin/cli/install_database.php \
      --lang=en \
      --adminuser=labadmin \
      --adminpass=LabAdmin1! \
      --adminemail=labadmin@example.com \
      --fullname="Moodle Grades Feedback IDOR Lab" \
      --shortname=lab \
      --agree-license; then
    fail_setup "install-database-failed"
  fi
else
  echo "IOC database-already-installed"
fi

echo "== wait login form =="
login_ok=0
for i in $(seq 1 60); do
  code="$(curl -sS -L --max-redirs 5 -o /tmp/moodle-grades-feedback-idor-login.html -w '%{http_code}' --max-time 8 \
    "${MOODLE_URL}/login/index.php" || true)"
  if [[ "${code}" == "200" ]] && grep -q 'logintoken\|username' /tmp/moodle-grades-feedback-idor-login.html; then
    login_ok=1
    echo "IOC login-ready attempt=${i} http=${code}"
    break
  fi
  echo "IOC login-wait attempt=${i} http=${code}"
  sleep 2
done
if [[ "${login_ok}" != 1 ]]; then
  fail_setup "login-not-ready"
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
