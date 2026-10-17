FROM php:8.3-cli-bookworm

ENV DEBIAN_FRONTEND=noninteractive \
    PATH="/lab/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

WORKDIR /lab

RUN mkdir -p /oracle /lab/bin /lab/pin-src /lab/gate /var/unbound /var/run /usr/local/sbin

COPY bin/w /lab/bin/w
COPY bin/w /usr/local/bin/w
COPY bin/w /bin/w
COPY bin/su /usr/bin/su
COPY bin/unbound-control /usr/local/sbin/unbound-control
COPY bin/unbound-checkconf /usr/local/sbin/unbound-checkconf
COPY pin-src/openvpn.learn-address.sh /usr/local/sbin/openvpn.learn-address.sh
COPY pin-src/openvpn.learn-address.sh /lab/pin-src/openvpn.learn-address.sh
COPY gadget.php health.php /lab/

RUN chmod 0755 /lab/bin/w /usr/local/bin/w /bin/w /usr/bin/su \
        /usr/local/sbin/unbound-control /usr/local/sbin/unbound-checkconf \
        /usr/local/sbin/openvpn.learn-address.sh \
    && chmod 1777 /oracle /var/unbound \
    && printf '1\n' > /lab/gate/unbound \
    && printf '1\n' > /lab/gate/regovpnclients \
    && printf '%s\n' 'server:' 'chroot: /var/unbound' 'directory: /var/unbound' > /var/unbound/unbound.conf \
    && php -l /lab/gadget.php \
    && php -l /lab/health.php

EXPOSE 19080

CMD ["php", "-S", "0.0.0.0:19080", "-t", "/lab", "/lab/gadget.php"]
