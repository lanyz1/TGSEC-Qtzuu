#!/usr/bin/env bash
set -euo pipefail

WWWROOT="${MOODLE_WWWROOT:-http://127.0.0.1:19590}"
DATAROOT="${MOODLE_DATAROOT:-/var/www/moodledata}"
DBHOST="${MOODLE_DBHOST:-db}"
DBNAME="${MOODLE_DBNAME:-moodle}"
DBUSER="${MOODLE_DBUSER:-moodle}"
DBPASS="${MOODLE_DBPASS:-LabDbPassw0rd!}"
ADMINUSER="${MOODLE_ADMINUSER:-labadmin}"
ADMINPASS="${MOODLE_ADMINPASS:-LabAdminPass1!}"
ADMINEMAIL="${MOODLE_ADMINEMAIL:-labadmin@example.com}"

chmod a+rwX /var/www/html /var/www/moodledata || true
mkdir -p /var/www/moodledata
chmod a+rwX /var/www/moodledata || true

echo "== wait for mariadb ${DBHOST} =="
php -r '
$host = getenv("MOODLE_DBHOST") ?: "db";
$user = getenv("MOODLE_DBUSER") ?: "moodle";
$pass = getenv("MOODLE_DBPASS") ?: "LabDbPassw0rd!";
$name = getenv("MOODLE_DBNAME") ?: "moodle";
for ($i = 0; $i < 60; $i++) {
    $mysqli = @new mysqli($host, $user, $pass, $name);
    if (!$mysqli->connect_error) {
        $mysqli->close();
        fwrite(STDOUT, "db-ready attempt=" . ($i + 1) . PHP_EOL);
        exit(0);
    }
    fwrite(STDOUT, "db-wait attempt=" . ($i + 1) . " err=" . $mysqli->connect_error . PHP_EOL);
    sleep(2);
}
fwrite(STDERR, "db-not-ready\n");
exit(1);
'

if [[ ! -f /var/www/html/public/version.php ]]; then
  echo "moodle-src-missing" >&2
  exit 1
fi

if [[ ! -f /var/www/html/config.php ]]; then
  echo "== admin/cli/install.php =="
  php /var/www/html/admin/cli/install.php \
    --non-interactive \
    --agree-license \
    --lang=en \
    --wwwroot="${WWWROOT}" \
    --dataroot="${DATAROOT}" \
    --dbtype=mariadb \
    --dbhost="${DBHOST}" \
    --dbname="${DBNAME}" \
    --dbuser="${DBUSER}" \
    --dbpass="${DBPASS}" \
    --prefix=mdl_ \
    --fullname="Grade items lab" \
    --shortname=labgradesite \
    --adminuser="${ADMINUSER}" \
    --adminpass="${ADMINPASS}" \
    --adminemail="${ADMINEMAIL}"
  php /var/www/html/admin/cli/cfg.php --name=noemailever --set=1 || true
  php /var/www/html/admin/cli/cfg.php --name=passwordpolicy --set=0 || true
fi

if [[ ! -f /var/www/moodledata/lab-oracle.json ]]; then
  echo "== seed.php =="
  php /opt/lab/seed.php
fi

echo "== apache2-foreground =="
exec apache2-foreground
