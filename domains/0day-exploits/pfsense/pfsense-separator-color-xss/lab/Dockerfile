FROM php:8.3-cli-bookworm

ENV DEBIAN_FRONTEND=noninteractive \
    PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

WORKDIR /lab

RUN mkdir -p /oracle /lab/pin-src

COPY gadget.php stubs.php health.php /lab/
COPY pin-src/ /lab/pin-src/

RUN php -l /lab/gadget.php \
    && php -l /lab/stubs.php \
    && php -l /lab/health.php \
    && php -l /lab/pin-src/util.inc.excerpt.php \
    && php -l /lab/pin-src/filter.inc.excerpt.php \
    && php -l /lab/pin-src/firewall_rules.php.excerpt.php \
    && php -l /lab/pin-src/firewall_nat.inc.excerpt.php

EXPOSE 19160

CMD ["php", "-S", "0.0.0.0:19160", "-t", "/lab", "/lab/gadget.php"]
