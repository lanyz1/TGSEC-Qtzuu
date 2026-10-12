#!/usr/bin/env bash
set -euo pipefail

DEST="/home/labuser/nowrite/PROFTPD-SFTP-COPY-FILE-WRITE-WITNESS"
rm -f "${DEST}"
mkdir -p /var/log/proftpd
touch /var/log/proftpd/proftpd.log /var/log/proftpd/sftp.log
tail -n 0 -F /var/log/proftpd/proftpd.log /var/log/proftpd/sftp.log &

exec proftpd -n -c /etc/proftpd/proftpd.conf
