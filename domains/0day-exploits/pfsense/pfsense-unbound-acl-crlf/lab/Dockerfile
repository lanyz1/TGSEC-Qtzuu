FROM php:8.3-cli-bookworm

ENV DEBIAN_FRONTEND=noninteractive \
    PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

RUN mkdir -p /lab/pin-src /lab/tmp /lab/run /oracle /var/unbound /usr/local/sbin \
    && useradd --system --no-create-home --user-group unbound

COPY bin/unbound /usr/local/sbin/unbound
COPY gadget.php stubs.php health.php /lab/
COPY pin-src/ /lab/pin-src/
COPY oracle/secret.conf /oracle/secret.conf

RUN chmod 0755 /usr/local/sbin/unbound \
    && chmod 0755 /oracle /var/unbound \
    && php -l /lab/gadget.php \
    && php -l /lab/stubs.php \
    && php -l /lab/health.php \
    && php -l /lab/pin-src/globals.inc.excerpt.php \
    && php -l /lab/pin-src/util.inc.excerpt.php \
    && php -l /lab/pin-src/unbound.inc.excerpt.php \
    && php -l /lab/pin-src/services_unbound_acls.php.excerpt.php \
    && php -l /usr/local/sbin/unbound

WORKDIR /lab
EXPOSE 19060

CMD ["php", "-S", "0.0.0.0:19060", "-t", "/lab", "/lab/gadget.php"]
