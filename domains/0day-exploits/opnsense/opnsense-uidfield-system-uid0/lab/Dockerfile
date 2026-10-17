FROM php:8.3-cli

LABEL lab=opnsense-uidfield-system-uid0

ENV DEBIAN_FRONTEND=noninteractive

RUN mkdir -p /lab /oracle /root/.ssh /usr/sbin

COPY lab /lab
COPY lab/stubs/pw /usr/sbin/pw

RUN chmod 0755 /usr/sbin/pw \
    && chmod 0700 /root/.ssh \
    && chmod 0755 /oracle

WORKDIR /lab

CMD ["sleep", "infinity"]
