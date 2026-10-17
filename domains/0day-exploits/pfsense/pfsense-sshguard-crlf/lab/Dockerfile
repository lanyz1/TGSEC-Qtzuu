FROM php:8.3-cli-bookworm

ENV DEBIAN_FRONTEND=noninteractive \
    PATH="/lab/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

WORKDIR /lab

RUN mkdir -p /oracle /lab/bin /lab/pin-src /usr/local/etc /usr/local/libexec /var/log

COPY bin/w /lab/bin/w
COPY bin/sshguard-backend-exec /lab/bin/sshguard-backend-exec
COPY bin/sshg-fw-pf /usr/local/libexec/sshg-fw-pf
COPY write-witness.sh /oracle/write-witness.sh
COPY gadget.php stubs.php health.php /lab/
COPY pin-src/ /lab/pin-src/

RUN chmod 0755 /lab/bin/w /lab/bin/sshguard-backend-exec \
        /usr/local/libexec/sshg-fw-pf /oracle/write-witness.sh \
    && chmod 1777 /oracle \
    && php -l /lab/gadget.php \
    && php -l /lab/stubs.php \
    && php -l /lab/pin-src/syslog.inc.excerpt.php \
    && php -l /lab/pin-src/system_advanced_admin.inc.excerpt.php \
    && php -l /lab/pin-src/util.inc.excerpt.php

EXPOSE 18950

CMD ["php", "-S", "0.0.0.0:18950", "-t", "/lab", "/lab/gadget.php"]
