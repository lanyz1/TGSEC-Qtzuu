FROM php:8.3-cli-bookworm

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        git \
        libicu-dev \
        unzip \
    && docker-php-ext-install intl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=composer:2 /usr/bin/composer /usr/bin/composer

WORKDIR /var/www/html

COPY composer.json /var/www/html/composer.json
RUN composer install --no-dev --no-interaction --no-progress --no-scripts \
    && php -r 'require "vendor/autoload.php"; echo "cakephp-autoload-ok\n";'

COPY send.php /var/www/html/send.php

CMD ["sleep", "infinity"]
