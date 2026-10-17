#!/bin/sh
# Pin excerpt pfsense/pfsense 9363ac5b8651a1c7a333180425ce7719070f95f9. Do not edit by hand.

unset TIMEZONE
# Fetch the timezone from /var/db/zoneinfo if present
if [ -f /var/db/zoneinfo ]; then
	TIMEZONE=$(cat /var/db/zoneinfo)
fi

/bin/cat >/usr/local/etc/php.ini <<EOF
; File generated from /etc/rc.php_ini_setup
date.timezone="${TIMEZONE}"
EOF
