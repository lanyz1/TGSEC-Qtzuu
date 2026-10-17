#!/bin/sh
set -eu
cd /lab
php /lab/gadget.php --write-nginx
nginx -t -c /lab/nginx.conf
nginx -c /lab/nginx.conf
exec php -S 0.0.0.0:19210 -t /lab /lab/gadget.php
