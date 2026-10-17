FROM php:8.3-cli-bookworm

ENV DEBIAN_FRONTEND=noninteractive \
    PATH="/oracle/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

# PATH stub `w` is the oracle. Absolute /sbin/ifconfig is a no-op so the
# leftover is the shell parse of the interpolated string, not host ifconfig.
RUN mkdir -p /oracle/bin /lab \
    && printf '%s\n' \
        '#!/bin/sh' \
        'printf "%s\n" "PFSENSE-CARP-VHID-WITNESS" > /oracle/PFSENSE-CARP-VHID-WITNESS' \
        > /oracle/bin/w \
    && chmod 0755 /oracle/bin/w \
    && printf '%s\n' '#!/bin/sh' 'exit 0' > /sbin/ifconfig \
    && chmod 0755 /sbin/ifconfig

COPY lab.php /lab/lab.php

WORKDIR /lab
EXPOSE 18830

CMD ["php", "-S", "0.0.0.0:18830", "-t", "/lab", "/lab/lab.php"]
