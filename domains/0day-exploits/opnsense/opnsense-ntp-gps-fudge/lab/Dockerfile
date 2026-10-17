FROM php:8.3-cli

WORKDIR /lab

RUN mkdir -p /var/etc /var/log/ntp /var/empty /oracle \
    && mknod /dev/cua0 c 1 3 \
    && chmod 666 /dev/cua0 \
    && test -c /dev/cua0

COPY lab/pin/ntpd.inc /lab/pin/ntpd.inc
COPY lab/pin/PIN.txt /lab/pin/PIN.txt
COPY lab/driver.php /lab/driver.php

CMD ["sleep", "infinity"]
