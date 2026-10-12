#!/usr/bin/env bash
set -euo pipefail

mkdir -p /home/labuser/tmp /var/run/proftpd /var/log/proftpd /tmp /etc/proftpd
chown labuser:labuser /home/labuser
chmod 755 /home/labuser
chmod 1777 /tmp /home/labuser/tmp

HASH="$(openssl passwd -6 -salt labslt01 labpass)"
printf 'labuser:%s:1000:1000::/home/labuser:/bin/false\n' "${HASH}" > /etc/proftpd/ftpd.passwd
printf 'labuser:x:1000:labuser\n' > /etc/proftpd/ftpd.group
chmod 600 /etc/proftpd/ftpd.passwd /etc/proftpd/ftpd.group

ASAN_LIB="$(ldd /usr/local/sbin/proftpd | awk '/libasan/{print $3; exit}')"
export LD_PRELOAD="${ASAN_LIB}:/usr/local/lib/liblabcrypt.so"
/usr/local/sbin/proftpd -t -c /etc/proftpd/proftpd.conf
exec /usr/local/sbin/proftpd -n -c /etc/proftpd/proftpd.conf
