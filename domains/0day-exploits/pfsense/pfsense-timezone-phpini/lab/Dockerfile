FROM php:8.3-cli-bookworm

ENV DEBIAN_FRONTEND=noninteractive \
    PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

WORKDIR /lab

RUN mkdir -p /lab/pin-src /oracle /var/db /usr/local/etc \
    && test -e /usr/share/zoneinfo/UTC

COPY gadget.php stubs.php health.php echo.php /lab/
COPY prepend.php /oracle/prepend.php
COPY pin-src/ /lab/pin-src/

RUN chmod 0755 /lab/pin-src/rc.php_ini_setup.excerpt.sh \
    && chmod 0644 /oracle/prepend.php /lab/echo.php \
    && chmod 1777 /oracle /var/db \
    && php -l /lab/gadget.php \
    && php -l /lab/stubs.php \
    && php -l /lab/health.php \
    && php -l /lab/echo.php \
    && php -l /oracle/prepend.php \
    && php -l /lab/pin-src/system.php.excerpt.php \
    && php -l /lab/pin-src/system.inc.excerpt.php \
    && php -l /lab/pin-src/guiconfig.inc.excerpt.php

EXPOSE 18940

CMD ["php", "-S", "0.0.0.0:18940", "-t", "/lab", "/lab/gadget.php"]
