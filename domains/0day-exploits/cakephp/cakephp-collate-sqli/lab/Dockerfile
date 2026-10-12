FROM php:8.3-cli

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        git \
        libicu-dev \
        libpq-dev \
        unzip \
    && docker-php-ext-install intl pdo_pgsql \
    && rm -rf /var/lib/apt/lists/*

COPY --from=composer:2 /usr/bin/composer /usr/bin/composer

WORKDIR /var/www/html

COPY composer.json /var/www/html/composer.json
RUN composer install --no-dev --no-interaction --no-progress --no-security-blocking \
    && test -f vendor/cakephp/database/Expression/StringExpression.php

COPY index.php /var/www/html/index.php

EXPOSE 80

CMD ["php", "-S", "0.0.0.0:80", "-t", "/var/www/html", "/var/www/html/index.php"]
