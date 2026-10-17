FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        iproute2 \
        kmod \
        php-cli \
        python3 \
        strongswan \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /lab /oracle /work /run /var/run

COPY gadget.php /lab/gadget.php
COPY apply.py /lab/apply.py
COPY entrypoint.sh /lab/entrypoint.sh
RUN chmod 755 /lab/entrypoint.sh /lab/apply.py \
    && php -r 'echo "php-ok\n";' \
    && python3 /lab/apply.py --self-test \
    && (ls -l /usr/libexec/ipsec/charon /usr/lib/ipsec/charon /usr/sbin/ipsec 2>/dev/null || true)

WORKDIR /lab
EXPOSE 18850

ENTRYPOINT ["/lab/entrypoint.sh"]
