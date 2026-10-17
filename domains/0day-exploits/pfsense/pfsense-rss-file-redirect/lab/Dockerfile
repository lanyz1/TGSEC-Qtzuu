FROM php:8.3-cli-bookworm

ENV DEBIAN_FRONTEND=noninteractive \
    PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

# pfSense WebGUI PHP ships curl; SimplePie File prefers curl_exec when present.
RUN apt-get update \
    && apt-get install -y --no-install-recommends libcurl4-openssl-dev \
    && docker-php-ext-install curl \
    && rm -rf /var/lib/apt/lists/*

# Pin composer.lock simplepie/simplepie 1.9.0 @ 76cccb1b2c5dcaf44f304c925ab30c0f48643992
ADD https://github.com/simplepie/simplepie/archive/76cccb1b2c5dcaf44f304c925ab30c0f48643992.tar.gz /tmp/simplepie.tar.gz

RUN mkdir -p /lab /oracle /lab/pin-src \
    && tar -xzf /tmp/simplepie.tar.gz -C /tmp \
    && mv /tmp/simplepie-76cccb1b2c5dcaf44f304c925ab30c0f48643992 /lab/simplepie \
    && rm -f /tmp/simplepie.tar.gz \
    && test -f /lab/simplepie/src/File.php \
    && grep -q '76cccb1b2c5dcaf44f304c925ab30c0f48643992' /lab/simplepie/src/File.php || true \
    && grep -q 'FILE_SOURCE_FILE_GET_CONTENTS' /lab/simplepie/src/File.php \
    && grep -q 'function fix_protocol' /lab/simplepie/src/Misc.php

COPY gadget.php redirect.php start.sh /lab/
COPY pin-src/ /lab/pin-src/

RUN chmod 0755 /lab/start.sh \
    && chmod 0755 /oracle \
    && php -l /lab/gadget.php \
    && php -l /lab/redirect.php \
    && php -l /lab/pin-src/is_url.inc.excerpt.php \
    && php -l /lab/simplepie/src/File.php \
    && php -l /lab/simplepie/src/SimplePie.php

WORKDIR /lab
EXPOSE 19100

CMD ["/lab/start.sh"]
