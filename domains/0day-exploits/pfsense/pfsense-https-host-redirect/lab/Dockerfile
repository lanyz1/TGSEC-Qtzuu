FROM php:8.3-cli-bookworm

ENV DEBIAN_FRONTEND=noninteractive \
    PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

RUN apt-get update \
    && apt-get install -y --no-install-recommends nginx-light \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /lab/pin-src /oracle \
    && rm -f /etc/nginx/sites-enabled/default

COPY stubs.php gadget.php health.php start.sh /lab/
COPY pin-src/ /lab/pin-src/

RUN chmod 0755 /lab/start.sh \
    && chmod 0755 /oracle \
    && php -l /lab/gadget.php \
    && php -l /lab/stubs.php \
    && php -l /lab/health.php \
    && php -l /lab/pin-src/system.inc.excerpt.php \
    && php -l /lab/pin-src/auth.inc.excerpt.php

WORKDIR /lab
EXPOSE 19210

CMD ["/lab/start.sh"]
