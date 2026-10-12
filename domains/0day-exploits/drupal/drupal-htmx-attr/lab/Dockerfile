FROM drupal:11.4.8-apache

ENV COMPOSER_ALLOW_SUPERUSER=1 \
    COMPOSER_MEMORY_LIMIT=-1

RUN printf 'memory_limit=512M\nmax_execution_time=180\n' \
    > /usr/local/etc/php/conf.d/lab.ini

WORKDIR /opt/drupal
RUN composer require drush/drush:^13 --no-interaction --no-progress
