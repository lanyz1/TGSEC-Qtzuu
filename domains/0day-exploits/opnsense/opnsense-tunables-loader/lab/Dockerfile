FROM php:8.3-cli

ENV DEBIAN_FRONTEND=noninteractive

WORKDIR /lab

COPY pin/system.inc /lab/pin/system.inc
COPY pin/Tunables.xml /lab/pin/Tunables.xml
COPY gadget.php /lab/gadget.php

RUN mkdir -p /boot /oracle \
    && printf '%s\n' 'ttyv0	"/usr/libexec/getty Pc"	xterm	on secure' > /etc/ttys

CMD ["sleep", "infinity"]
