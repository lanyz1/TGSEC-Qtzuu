FROM php:8.3-cli-bookworm

ENV DEBIAN_FRONTEND=noninteractive \
    PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

WORKDIR /lab

RUN mkdir -p /lab/pin-src /oracle /var/db/cpelements /usr/local/captiveportal

COPY gadget.php stubs.php health.php /lab/
COPY pin-src/ /lab/pin-src/

RUN chmod 0755 /oracle /var/db/cpelements /usr/local/captiveportal \
    && php -l /lab/gadget.php \
    && php -l /lab/stubs.php \
    && php -l /lab/health.php \
    && php -l /lab/pin-src/globals.inc.excerpt.php \
    && php -l /lab/pin-src/util.inc.excerpt.php \
    && php -l /lab/pin-src/captiveportal.inc.excerpt.php \
    && php -l /lab/pin-src/services_captiveportal_filemanager.php.excerpt.php

EXPOSE 19000

CMD ["php", "-S", "0.0.0.0:19000", "-t", "/lab", "/lab/gadget.php"]
