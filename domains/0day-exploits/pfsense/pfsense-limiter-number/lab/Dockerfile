FROM php:8.3-cli-bookworm

ENV DEBIAN_FRONTEND=noninteractive \
    PATH="/lab/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

WORKDIR /lab

RUN mkdir -p /oracle /lab/bin /lab/tmp \
    && ln -sf /bin/true /sbin/dnctl

COPY w /lab/bin/w
COPY gadget.php /lab/gadget.php

RUN chmod 0755 /lab/bin/w \
    && chmod 1777 /oracle /lab/tmp

EXPOSE 18840

CMD ["php", "-S", "0.0.0.0:18840", "-t", "/lab", "/lab/gadget.php"]
