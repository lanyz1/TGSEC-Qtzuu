FROM php:8.3-cli-bookworm

ENV DEBIAN_FRONTEND=noninteractive \
    PATH="/lab/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

WORKDIR /lab

RUN mkdir -p /oracle /lab/bin /lab/tmp /lab/db /lab/etc /lab/pin-src

COPY bin/voucher /lab/bin/voucher
COPY bin/voucher /usr/local/bin/voucher
COPY gadget.php stubs.php health.php /lab/
COPY pin-src/ /lab/pin-src/

RUN chmod 0755 /lab/bin/voucher /usr/local/bin/voucher \
    && chmod 1777 /oracle /lab/tmp /lab/db \
    && php -m | grep -i sqlite3 \
    && php -l /lab/gadget.php \
    && php -l /lab/stubs.php \
    && php -l /lab/health.php \
    && php -l /lab/pin-src/captiveportal.inc.excerpt.php \
    && php -l /lab/pin-src/voucher.inc.excerpt.php

EXPOSE 19280

CMD ["php", "-S", "0.0.0.0:19280", "-t", "/lab", "/lab/gadget.php"]
