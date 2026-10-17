FROM php:8.3-cli

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends sed \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /oracle /work /lab/templates

COPY templates/ /lab/templates/
COPY apply_mirror.sh /lab/apply_mirror.sh
COPY sanitize.php /lab/sanitize.php
COPY lab_server.php /lab/lab_server.php

RUN chmod 0755 /lab/apply_mirror.sh \
    && test -f /lab/templates/OPNsense.conf.sample \
    && grep -q 'signature_type: "fingerprints"' /lab/templates/OPNsense.conf.sample \
    && grep -q 'pkg.opnsense.org' /lab/templates/OPNsense.conf.sample \
    && grep -q '26.7/latest' /lab/templates/OPNsense.conf.sample

WORKDIR /lab
EXPOSE 18860

CMD ["php", "-S", "0.0.0.0:18860", "-t", "/lab", "/lab/lab_server.php"]
