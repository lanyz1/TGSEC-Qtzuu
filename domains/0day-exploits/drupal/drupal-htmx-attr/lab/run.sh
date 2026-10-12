#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-drupal-htmx-attr}"
export PYTHONUNBUFFERED=1
export DRUPAL_URL="${DRUPAL_URL:-http://127.0.0.1:19480}"

LABEL="drupal-htmx-attr"
WITNESS="DRUPAL-HTMX-ATTR-WITNESS"

down() {
  echo "== docker compose down -v =="
  docker compose -p "${COMPOSE_PROJECT_NAME}" down -v --remove-orphans || true
}

trap down EXIT

fail_setup() {
  local reason="$1"
  echo "FAIL ${LABEL} ${reason} ${WITNESS}" | tee poc-last-run.txt
  docker compose -p "${COMPOSE_PROJECT_NAME}" logs --no-color --tail=80 || true
  exit 1
}

echo "== docker compose down (clean) =="
down
trap down EXIT

echo "== docker compose up --build =="
up_ok=0
for attempt in $(seq 1 5); do
  if docker compose -p "${COMPOSE_PROJECT_NAME}" up --build -d; then
    up_ok=1
    break
  fi
  echo "compose-up-retry attempt=${attempt}"
  sleep 8
  down
done
if [[ "${up_ok}" != 1 ]]; then
  fail_setup "compose-up-failed"
fi

echo "== wait for apache 127.0.0.1:19480 =="
ok=0
for i in $(seq 1 90); do
  if python3 - <<'PY'
import socket
sock = socket.create_connection(("127.0.0.1", 19480), 2)
sock.close()
PY
  then
    ok=1
    echo "apache-ready attempt=${i}"
    break
  fi
  echo "apache-wait attempt=${i}"
  sleep 2
done
if [[ "${ok}" != 1 ]]; then
  fail_setup "apache-not-ready"
fi

echo "== site-install standard (mysql via drush) =="
install_ok=0
if docker compose -p "${COMPOSE_PROJECT_NAME}" exec -T drupal \
  drush site:install standard \
  --db-url=mysql://drupal:drupal@db:3306/drupal \
  --site-name=Lab \
  --account-name=admin \
  --account-pass=admin \
  --account-mail=admin@lab.invalid \
  --yes; then
  install_ok=1
fi
if [[ "${install_ok}" != 1 ]]; then
  fail_setup "site-install-failed"
fi

echo "== chown sites for apache =="
docker compose -p "${COMPOSE_PROJECT_NAME}" exec -T drupal bash -c '
set -euo pipefail
chown -R www-data:www-data /opt/drupal/web/sites
chmod 775 /opt/drupal/web/sites/default
chmod 775 /opt/drupal/web/sites/default/files || true
'

echo "== append trusted hosts and jsonapi write =="
docker compose -p "${COMPOSE_PROJECT_NAME}" exec -T drupal php -r '
$dir = "/opt/drupal/web/sites/default";
$path = $dir . "/settings.php";
chmod($dir, 0775);
chmod($path, 0644);
$extra = <<<PHP

\$settings["trusted_host_patterns"] = [
  "^127\\.0\\.0\\.1\$",
  "^localhost\$",
  "^drupal\$",
];
\$config["jsonapi.settings"]["read_only"] = FALSE;
\$config["system.performance"]["css"]["preprocess"] = FALSE;
\$config["system.performance"]["js"]["preprocess"] = FALSE;
PHP;
file_put_contents($path, $extra, FILE_APPEND);
chmod($path, 0444);
echo "settings-appended\n";
'

echo "== wait HTTP 200 on / =="
ready=0
for i in $(seq 1 60); do
  code="$(curl -sS -o /dev/null -w "%{http_code}" --max-time 8 "${DRUPAL_URL}/" || true)"
  if [[ "${code}" == "200" ]]; then
    ready=1
    echo "http-ready attempt=${i} code=${code}"
    break
  fi
  echo "http-wait attempt=${i} code=${code}"
  sleep 2
done
if [[ "${ready}" != 1 ]]; then
  fail_setup "http-not-ready"
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
