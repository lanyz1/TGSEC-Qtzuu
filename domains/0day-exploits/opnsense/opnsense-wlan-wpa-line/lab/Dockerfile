FROM php:8.3-cli

ENV DEBIAN_FRONTEND=noninteractive

WORKDIR /lab

COPY pin/ /lab/pin/
COPY stubs/ /lab/stubs/
COPY lab.php /lab/lab.php

RUN mkdir -p /var/etc /oracle /tmp \
    && php -l /lab/pin/interfaces.inc \
    && php -l /lab/pin/TextField.php \
    && php -l /lab/stubs/helpers.php \
    && php -l /lab/stubs/interfaces.lib.inc \
    && php -l /lab/stubs/Wlan.php \
    && php -l /lab/lab.php \
    && grep -F "wpa']['identity']" /lab/pin/interfaces.inc \
    && grep -F '<identity type="TextField"/>' /lab/pin/Wlan.xml \
    && grep -F 'internalAllowNewlines = true' /lab/pin/TextField.php

EXPOSE 18840

CMD ["php", "-S", "0.0.0.0:18840", "-t", "/lab", "/lab/lab.php"]
