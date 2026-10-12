FROM debian:bookworm-slim AS build

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        git \
    && rm -rf /var/lib/apt/lists/*

# Pin: GitHub proftpd/proftpd tag v1.3.9d
# commit f59f248e26bdfa514443e42bf72a145641df635d
RUN git clone --depth 1 --branch v1.3.9d https://github.com/proftpd/proftpd.git /src/proftpd

WORKDIR /src/proftpd

RUN grep -F 'PROFTPD_VERSION_TEXT' include/version.h \
    && grep -F '"1.3.9d"' include/version.h \
    && grep -F '0x0001030908' include/version.h \
    && ./configure \
        --prefix=/usr/local \
        --sysconfdir=/etc/proftpd \
        --localstatedir=/var/proftpd \
        --disable-auth-pam \
        --disable-cap \
        --disable-ident \
        --disable-nls \
        --with-modules=mod_copy:mod_site_misc \
    && make -j"$(nproc)" \
    && make install \
    && /usr/local/sbin/proftpd -v

FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        openssl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 1000 labuser \
    && useradd --uid 1000 --gid 1000 --home-dir /home/labuser --shell /bin/false labuser \
    && install -d -m 0755 /etc/proftpd /var/proftpd /run \
    && hash="$(openssl passwd -6 -salt labhash labpass)" \
    && printf '%s\n' "labuser:${hash}:1000:1000:lab user:/home/labuser:/bin/false" \
        > /etc/proftpd/ftpd.passwd \
    && printf '%s\n' "labuser:x:1000:labuser" > /etc/proftpd/ftpd.group \
    && chmod 0600 /etc/proftpd/ftpd.passwd \
    && chmod 0640 /etc/proftpd/ftpd.group

COPY --from=build /usr/local/sbin/proftpd /usr/local/sbin/proftpd
COPY proftpd.conf /etc/proftpd/proftpd.conf
COPY entrypoint.sh /entrypoint.sh

RUN chmod 0755 /entrypoint.sh \
    && /usr/local/sbin/proftpd -v \
    && /usr/local/sbin/proftpd -t -c /etc/proftpd/proftpd.conf

EXPOSE 21 18721-18730

ENTRYPOINT ["/entrypoint.sh"]
