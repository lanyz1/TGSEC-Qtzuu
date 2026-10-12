# phpMyAdmin 5.2.3 lab: CustomServer WebAuthn (no web-auth/webauthn-lib).
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

# Git clone lockfile still lists webauthn-lib. Official tarball does not ship it.
# CustomServer is used iff Webauthn\\Server is absent.
RUN git config --global --add safe.directory /var/www/html \
  && composer install --no-dev --no-interaction --prefer-dist --no-scripts \
  && rm -rf vendor/web-auth \
  && composer dump-autoload -o --no-interaction \
  && mkdir -p /tmp/pma /var/www/html/tmp \
  && chown -R www-data:www-data /tmp/pma /var/www/html/tmp \
  && php -r 'require "vendor/autoload.php"; exit(class_exists("Webauthn\\Server") ? 1 : 0);'

EXPOSE 80
