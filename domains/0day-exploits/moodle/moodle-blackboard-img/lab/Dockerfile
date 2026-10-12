FROM php:8.3-cli-bookworm

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends libzip-dev unzip \
    && docker-php-ext-install zip \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /lab

COPY gadget.php /lab/gadget.php
COPY pin-src /lab/pin-src

RUN mkdir -p /var/www/html /var/www/moodledata/temp /var/www/moodledata/draft

EXPOSE 19560

CMD ["php", "-S", "0.0.0.0:19560", "-t", "/lab", "/lab/gadget.php"]
