ARG OLS_IMAGE=litespeedtech/openlitespeed:1.9.3-lsphp84
FROM ${OLS_IMAGE}

LABEL lab=openlitespeed-dup-cookie-litespeed-role

RUN mkdir -p /var/www/vhosts/localhost/html
COPY www/cookie.php /var/www/vhosts/localhost/html/cookie.php
RUN chmod 644 /var/www/vhosts/localhost/html/cookie.php
