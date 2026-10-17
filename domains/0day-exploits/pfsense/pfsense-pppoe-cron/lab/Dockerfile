FROM php:8.3-cli-bookworm

ENV DEBIAN_FRONTEND=noninteractive \
    PATH="/lab/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

RUN mkdir -p /lab/pin-src /lab/bin /oracle /var/etc /var/run

COPY bin/w /lab/bin/w
COPY bin/w /usr/local/bin/w
COPY bin/w /bin/w
COPY gadget.php stubs.php health.php /lab/
COPY pin-src/ /lab/pin-src/

RUN chmod 0755 /lab/bin/w /usr/local/bin/w /bin/w \
    && chmod 0755 /oracle \
    && php -l /lab/gadget.php \
    && php -l /lab/stubs.php \
    && php -l /lab/pin-src/globals.inc.excerpt.php \
    && php -l /lab/pin-src/util.inc.excerpt.php \
    && php -l /lab/pin-src/interfaces.inc.excerpt.php \
    && php -l /lab/pin-src/services.inc.excerpt.php \
    && php -l /lab/pin-src/interfaces_ppps_edit.php.excerpt.php

WORKDIR /lab
EXPOSE 18970

CMD ["php", "-S", "0.0.0.0:18970", "-t", "/lab", "/lab/gadget.php"]
