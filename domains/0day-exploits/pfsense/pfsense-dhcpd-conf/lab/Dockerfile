FROM php:8.3-cli-bookworm

ENV DEBIAN_FRONTEND=noninteractive \
    PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

RUN mkdir -p /lab/pin-src /lab/var/dhcpd/etc /lab/var/etc /lab/var/run /oracle

COPY gadget.php stubs.php health.php /lab/
COPY pin-src/ /lab/pin-src/

RUN chmod 0755 /oracle /lab/var/dhcpd /lab/var/dhcpd/etc /lab/var/etc /lab/var/run \
    && php -l /lab/gadget.php \
    && php -l /lab/stubs.php \
    && php -l /lab/health.php \
    && php -l /lab/pin-src/services.inc.excerpt.php \
    && php -l /lab/pin-src/services_dhcp_edit.php.excerpt.php

WORKDIR /lab
EXPOSE 19250

CMD ["php", "-S", "0.0.0.0:19250", "-t", "/lab", "/lab/gadget.php"]
