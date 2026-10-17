FROM php:8.3-cli-bookworm

ENV DEBIAN_FRONTEND=noninteractive \
    PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

RUN mkdir -p /lab/pin-src /lab/tmp /lab/conf /oracle

COPY gadget.php stubs.php health.php /lab/
COPY pin-src/ /lab/pin-src/

RUN chmod 0755 /oracle /lab/tmp /lab/conf \
    && php -l /lab/gadget.php \
    && php -l /lab/stubs.php \
    && php -l /lab/health.php \
    && php -l /lab/pin-src/uploadconfig.php.excerpt.php \
    && php -l /lab/pin-src/priv.defs.inc.excerpt.php \
    && php -l /lab/pin-src/diag_backup.php.excerpt.php

WORKDIR /lab
EXPOSE 19030

CMD ["php", "-S", "0.0.0.0:19030", "-t", "/lab", "/lab/gadget.php"]
