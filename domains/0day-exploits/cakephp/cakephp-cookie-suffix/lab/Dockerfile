FROM php:8.3-cli-bookworm

ENV DEBIAN_FRONTEND=noninteractive \
    COMPOSER_ALLOW_SUPERUSER=1 \
    COMPOSER_NO_INTERACTION=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        git \
        libicu-dev \
        libonig-dev \
        unzip \
    && docker-php-ext-install intl mbstring \
    && rm -rf /var/lib/apt/lists/*

COPY --from=composer:2 /usr/bin/composer /usr/bin/composer

# Pin cakephp/cakephp tag 5.4.2 (POC-READY.md).
WORKDIR /opt/cakephp
RUN git clone --depth 1 --branch 5.4.2 https://github.com/cakephp/cakephp.git . \
    && test "$(git rev-parse HEAD)" = "887b641de9f7aba06071f98f17edcbc573cbcf63" \
    && grep -qx "5.4.2" VERSION.txt \
    && composer install --no-dev --prefer-dist --no-progress

COPY oracle.php /app/oracle.php

WORKDIR /app
EXPOSE 8080

CMD ["php", "-S", "0.0.0.0:8080", "-t", "/app", "/app/oracle.php"]
