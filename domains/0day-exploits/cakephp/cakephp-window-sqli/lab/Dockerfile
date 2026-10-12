FROM php:8.2-apache

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        git \
        libsqlite3-dev \
        unzip \
    && docker-php-ext-install pdo_sqlite \
    && rm -rf /var/lib/apt/lists/*

COPY --from=composer:2 /usr/bin/composer /usr/bin/composer

WORKDIR /var/www/html

COPY composer.json /var/www/html/composer.json
RUN composer install --no-dev --no-interaction --no-progress --no-security-blocking

COPY index.php /var/www/html/index.php
RUN chown -R www-data:www-data /var/www/html
