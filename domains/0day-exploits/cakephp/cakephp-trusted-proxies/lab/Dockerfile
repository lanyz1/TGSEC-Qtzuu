FROM php:8.3-cli-bookworm

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        git \
        libicu-dev \
        unzip \
    && docker-php-ext-install intl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=composer:2 /usr/bin/composer /usr/bin/composer

WORKDIR /app
COPY composer.json /app/composer.json
RUN composer install --no-dev --no-interaction --prefer-dist --no-progress \
    && php -r 'require "vendor/autoload.php"; echo file_get_contents("vendor/cakephp/cakephp/VERSION.txt");'

COPY index.php /app/index.php

EXPOSE 8080
CMD ["php", "-S", "0.0.0.0:8080", "-t", "/app", "/app/index.php"]
