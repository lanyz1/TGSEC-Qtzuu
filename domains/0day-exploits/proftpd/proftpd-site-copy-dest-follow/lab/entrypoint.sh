#!/usr/bin/env bash
set -euo pipefail

install -d -m 0755 -o labuser -g labuser \
  /home/labuser \
  /home/labuser/readable \
  /home/labuser/upload \
  /home/labuser/secret

printf '%s\n' "PROFTPD-SITE-COPY-DEST-FOLLOW-WITNESS" > /home/labuser/readable/src.txt
printf '%s\n' "ORIGINAL" > /home/labuser/secret/victim

chown labuser:labuser /home/labuser/readable/src.txt /home/labuser/secret/victim
chmod 0644 /home/labuser/readable/src.txt /home/labuser/secret/victim
chmod 0755 /home/labuser /home/labuser/readable /home/labuser/secret
chmod 0775 /home/labuser/upload
chown labuser:labuser /home/labuser/upload

exec /usr/local/sbin/proftpd -n -c /etc/proftpd/proftpd.conf
