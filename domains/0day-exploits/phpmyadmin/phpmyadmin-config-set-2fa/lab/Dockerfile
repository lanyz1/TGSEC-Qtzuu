# phpMyAdmin 5.2.3 lab: POST /config/set clears 2FA without step-up.
FROM php:8.2-apache

ENV COMPOSER_ALLOW_SUPERUSER=1

RUN apt-get update && apt-get install -y --no-install-recommends \
      git unzip libzip-dev libonig-dev \
  && docker-php-ext-install mysqli mbstring \
  && rm -rf /var/lib/apt/lists/* \
  && curl -fsSL https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer

WORKDIR /var/www/html
COPY src/ /var/www/html/
COPY config.inc.php /var/www/html/config.inc.php

RUN git config --global --add safe.directory /var/www/html \
  && composer install --no-dev --no-interaction --prefer-dist --no-scripts \
  && mkdir -p /tmp/pma /var/www/html/tmp \
  && chown -R www-data:www-data /tmp/pma /var/www/html/tmp

EXPOSE 80
