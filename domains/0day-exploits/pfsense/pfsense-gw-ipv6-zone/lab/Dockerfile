FROM php:8.3-cli-bookworm

ENV DEBIAN_FRONTEND=noninteractive \
    PATH="/lab/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

WORKDIR /lab

RUN mkdir -p /oracle /lab/bin /lab/pin-src /lab/run /lab/etc

COPY bin/w /lab/bin/w
COPY bin/dpinger /usr/local/bin/dpinger
COPY gadget.php stubs.php health.php /lab/
COPY pin-src/ /lab/pin-src/

RUN chmod 0755 /lab/bin/w /usr/local/bin/dpinger \
    && chmod 1777 /oracle /lab/run \
    && php -l /lab/gadget.php \
    && php -l /lab/stubs.php \
    && php -l /lab/pin-src/Net_IPv6.php \
    && php -l /lab/pin-src/util.inc.excerpt.php \
    && php -l /lab/pin-src/gwlb.inc.excerpt.php

EXPOSE 18930

CMD ["php", "-S", "0.0.0.0:18930", "-t", "/lab", "/lab/gadget.php"]
