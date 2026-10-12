FROM php:8.3-cli-bookworm

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        git \
        unzip \
        libicu-dev \
        libonig-dev \
        libzip-dev \
    && docker-php-ext-install intl mbstring \
    && rm -rf /var/lib/apt/lists/*

COPY --from=composer:2 /usr/bin/composer /usr/bin/composer

WORKDIR /lab

# Pin CakePHP 5.4.2 (887b641de9f7aba06071f98f17edcbc573cbcf63).
RUN git clone --depth 1 --branch 5.4.2 https://github.com/cakephp/cakephp.git pin \
    && test "$(git -C pin rev-parse HEAD)" = "887b641de9f7aba06071f98f17edcbc573cbcf63"

WORKDIR /lab/pin
RUN composer install --no-dev --no-interaction --prefer-dist

WORKDIR /lab
COPY lab_server.php /lab/lab_server.php

EXPOSE 19460
CMD ["php", "-S", "0.0.0.0:19460", "-t", "/lab", "/lab/lab_server.php"]
