FROM php:8.3-cli-bookworm

ENV DEBIAN_FRONTEND=noninteractive \
    PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

RUN mkdir -p /lab/pin-src /lab/var/etc /conf /oracle

COPY gadget.php stubs.php health.php /lab/
COPY pin-src/ /lab/pin-src/

RUN chmod 0755 /oracle /conf /lab/var/etc \
    && php -l /lab/gadget.php \
    && php -l /lab/stubs.php \
    && php -l /lab/health.php \
    && php -l /lab/pin-src/util.inc.excerpt.php \
    && php -l /lab/pin-src/dyndns.class.excerpt.php \
    && php -l /lab/pin-src/services_dyndns_edit.php.excerpt.php

WORKDIR /lab
EXPOSE 19270

CMD ["php", "-S", "0.0.0.0:19270", "-t", "/lab", "/lab/gadget.php"]
