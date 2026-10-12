FROM php:8.3-cli

ENV DEBIAN_FRONTEND=noninteractive

RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        libfreetype6-dev \
        libicu-dev \
        libjpeg62-turbo-dev \
        libonig-dev \
        libpng-dev \
        libxml2-dev \
        libzip-dev \
        unzip \
    ; \
    docker-php-ext-configure gd --with-freetype --with-jpeg; \
    docker-php-ext-install -j"$(nproc)" \
        exif \
        gd \
        intl \
        mbstring \
        mysqli \
        opcache \
        pdo_mysql \
        soap \
        zip \
    ; \
    rm -rf /var/lib/apt/lists/*

COPY php-lab.ini /usr/local/etc/php/conf.d/zz-lab.ini
COPY config.php /opt/lab/config.php
COPY seed.php /opt/lab/seed.php
COPY entrypoint.sh /opt/lab/entrypoint.sh

RUN mkdir -p /var/www/moodledata /var/www/html \
    && chmod +x /opt/lab/entrypoint.sh

WORKDIR /var/www/html
EXPOSE 80
ENTRYPOINT ["/opt/lab/entrypoint.sh"]
