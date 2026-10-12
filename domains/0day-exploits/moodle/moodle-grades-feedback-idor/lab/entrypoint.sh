#!/bin/sh
set -eu

html=/var/www/html
pin=/opt/moodle-pin

if [ ! -f "${html}/public/version.php" ]; then
  echo "IOC copy-pin start"
  mkdir -p "${html}"
  tar -C "${pin}" --exclude=.git -cf - . | tar -C "${html}" -xf -
  echo "IOC copy-pin done"
fi

cp /opt/lab/config.php "${html}/config.php"
mkdir -p /var/www/moodledata
cd "${html}"
exec php -S 0.0.0.0:80 -t "${html}/public"
