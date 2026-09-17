FROM php:8.4-apache

RUN apt-get update && apt-get install -y --no-install-recommends \
        libfreetype6-dev libjpeg62-turbo-dev libpng-dev libicu-dev libxml2-dev \
        libxslt1-dev libzip-dev libsodium-dev libonig-dev libcurl4-openssl-dev \
        libssh2-1-dev unzip git default-mysql-client cron sendmail \
    && docker-php-ext-configure gd --with-freetype --with-jpeg \
    && docker-php-ext-install -j"$(nproc)" \
        bcmath ctype curl dom ftp gd intl mbstring opcache pdo_mysql \
        simplexml soap sockets sodium xsl zip \
    && a2enmod rewrite headers \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Magento is served from pub/
RUN sed -i 's|/var/www/html|/var/www/html/pub|g' /etc/apache2/sites-available/000-default.conf \
    && sed -i 's|<Directory /var/www/>|<Directory /var/www/html/pub/>|' /etc/apache2/apache2.conf \
    && sed -i 's/AllowOverride None/AllowOverride All/g' /etc/apache2/apache2.conf

RUN { \
      echo 'memory_limit=2G'; \
      echo 'max_execution_time=600'; \
      echo 'upload_max_filesize=64M'; \
      echo 'post_max_size=64M'; \
      echo 'opcache.enable=1'; \
      echo 'opcache.save_comments=1'; \
      echo 'sendmail_path=/bin/true'; \
    } > /usr/local/etc/php/conf.d/zz-magento.ini

COPY --from=composer:2 /usr/bin/composer /usr/bin/composer

WORKDIR /var/www/html
CMD ["apache2-foreground"]
