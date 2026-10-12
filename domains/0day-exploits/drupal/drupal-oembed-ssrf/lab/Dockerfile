FROM php:8.3-cli-bookworm

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    COMPOSER_ALLOW_SUPERUSER=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        git \
        python3 \
        unzip \
    && rm -rf /var/lib/apt/lists/*

COPY --from=composer:2 /usr/bin/composer /usr/bin/composer

WORKDIR /lab

COPY composer.json /lab/composer.json
RUN composer install --no-dev --no-interaction --no-progress

COPY pin /lab/pin
COPY gadget.php firsthop.py oracle.py /lab/

CMD ["sleep", "infinity"]
