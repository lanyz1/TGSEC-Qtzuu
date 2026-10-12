FROM php:8.2-apache

RUN apt-get update \
  && apt-get install -y --no-install-recommends \
    wait-for-it \
    unzip \
    libfreetype6-dev \
    libjpeg62-turbo-dev \
    libpng-dev \
    libzip-dev \
    libcurl4-openssl-dev \
    libwebp-dev \
  && docker-php-ext-configure gd --with-freetype --with-jpeg --with-webp \
  && docker-php-ext-install -j$(nproc) gd zip mysqli curl \
  && docker-php-ext-enable gd zip mysqli curl \
  && a2enmod rewrite \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /var/www/html
