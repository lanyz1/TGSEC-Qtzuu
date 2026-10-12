FROM php:8.3-cli

ENV DEBIAN_FRONTEND=noninteractive

RUN docker-php-ext-install mysqli

WORKDIR /var/www/html
COPY index.php /var/www/html/index.php

EXPOSE 80

CMD ["php", "-S", "0.0.0.0:80", "-t", "/var/www/html"]
