FROM php:8.3-cli-bookworm

ENV DEBIAN_FRONTEND=noninteractive \
    PATH="/lab/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

WORKDIR /lab

RUN mkdir -p /oracle /lab/bin /lab/tmp /lab/pin-src

COPY bin/w /lab/bin/w
COPY bin/w /usr/local/bin/w
COPY bin/w /bin/w
COPY bin/ifconfig /sbin/ifconfig
COPY gadget.php stubs.php health.php /lab/
COPY pin-src/ /lab/pin-src/

RUN chmod 0755 /lab/bin/w /usr/local/bin/w /bin/w /sbin/ifconfig \
    && chmod 1777 /oracle /lab/tmp \
    && php -l /lab/gadget.php \
    && php -l /lab/stubs.php \
    && php -l /lab/pin-src/globals.inc.excerpt.php \
    && php -l /lab/pin-src/util.inc.excerpt.php \
    && php -l /lab/pin-src/interfaces.inc.excerpt.php \
    && php -l /lab/pin-src/interfaces_assign.php.excerpt.php \
    && php -l /lab/pin-src/interfaces.php.excerpt.php

EXPOSE 18920

CMD ["php", "-S", "0.0.0.0:18920", "-t", "/lab", "/lab/gadget.php"]
