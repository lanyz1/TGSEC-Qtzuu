# Moodle v5.2.3 (tag v5.2.3, commit 344232c153). PHP for the live pin, not a gadget.
FROM php:8.3-apache-bookworm

ENV DEBIAN_FRONTEND=noninteractive
ENV APACHE_DOCUMENT_ROOT=/var/www/html/public

RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        git \
        libcurl4-openssl-dev \
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
        mysqli \
        opcache \
        soap \
        zip \
    ; \
    a2enmod rewrite; \
    rm -rf /var/lib/apt/lists/*

RUN set -eux; \
    sed -ri -e 's!/var/www/html!/var/www/html/public!g' /etc/apache2/sites-available/*.conf; \
    sed -ri -e 's!<Directory /var/www/>!<Directory /var/www/html/public/>!g' \
        /etc/apache2/apache2.conf; \
    { \
        echo 'max_input_vars=5000'; \
        echo 'memory_limit=512M'; \
        echo 'upload_max_filesize=64M'; \
        echo 'post_max_size=64M'; \
    } > /usr/local/etc/php/conf.d/moodle.ini

RUN mkdir -p /var/www/moodledata /opt/lab \
    && chown -R www-data:www-data /var/www/moodledata

COPY entrypoint.sh /opt/lab/entrypoint.sh
COPY seed.php /opt/lab/seed.php
RUN chmod +x /opt/lab/entrypoint.sh

WORKDIR /var/www/html
EXPOSE 80
ENTRYPOINT ["/opt/lab/entrypoint.sh"]
