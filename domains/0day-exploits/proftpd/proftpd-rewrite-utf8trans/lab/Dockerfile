FROM debian:bookworm-slim AS build

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        git \
        libcrypt-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src/proftpd

# Pin: tag v1.3.9d commit f59f248e26bdfa514443e42bf72a145641df635d
RUN git clone --depth 1 --branch v1.3.9d https://github.com/proftpd/proftpd.git . \
    && grep -q 'PROFTPD_VERSION_TEXT[[:space:]]*"1.3.9d"' include/version.h \
    && grep -q 'PROFTPD_VERSION_NUMBER[[:space:]]*0x0001030908' include/version.h \
    && grep -n 'rewrite_map_int_utf8trans' contrib/mod_rewrite.c \
    && grep -n 'rewrite_utf8_to_ucs4' contrib/mod_rewrite.c

ENV CFLAGS="-g -O1 -fsanitize=address -fno-omit-frame-pointer" \
    LDFLAGS="-fsanitize=address" \
    ASAN_OPTIONS="detect_leaks=0:abort_on_error=0"

RUN ./configure \
        --prefix=/usr/local \
        --sysconfdir=/etc/proftpd \
        --localstatedir=/var/run/proftpd \
        --with-modules=mod_rewrite \
        --disable-auth-pam \
        --disable-cap \
        --disable-nls \
        --disable-ident \
    && make -j"$(nproc)" \
    && install -d /usr/local/sbin /usr/local/lib \
    && install -m 0755 proftpd /usr/local/sbin/proftpd \
    && /usr/local/sbin/proftpd -v \
    && (ldd /usr/local/sbin/proftpd | grep -E 'libasan' \
        || nm -D /usr/local/sbin/proftpd | grep -E '__asan' | head)

COPY conf/labcrypt.c /tmp/labcrypt.c
RUN CFLAGS= LDFLAGS= gcc -O2 -fPIC -shared -o /usr/local/lib/liblabcrypt.so /tmp/labcrypt.c

FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive \
    ASAN_OPTIONS=detect_leaks=0:abort_on_error=1:halt_on_error=1:log_path=/tmp/asan

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        libasan8 \
        libcrypt1 \
        openssl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -g 1000 labuser \
    && useradd -u 1000 -g 1000 -d /home/labuser -s /bin/false labuser \
    && mkdir -p \
        /home/labuser/tmp \
        /etc/proftpd \
        /var/run/proftpd \
        /var/log/proftpd \
        /tmp \
    && chown labuser:labuser /home/labuser \
    && chmod 755 /home/labuser \
    && chmod 1777 /tmp /home/labuser/tmp

COPY --from=build /usr/local /usr/local
COPY conf/proftpd.conf /etc/proftpd/proftpd.conf
COPY conf/entrypoint.sh /entrypoint.sh

RUN chmod 0755 /entrypoint.sh \
    && printf 'labuser:x:1000:1000::/home/labuser:/bin/false\n' > /etc/proftpd/ftpd.passwd \
    && printf 'labuser:x:1000:labuser\n' > /etc/proftpd/ftpd.group \
    && chmod 600 /etc/proftpd/ftpd.passwd /etc/proftpd/ftpd.group \
    && /usr/local/sbin/proftpd -v \
    && /usr/local/sbin/proftpd -t -c /etc/proftpd/proftpd.conf

EXPOSE 21 18741-18750

ENTRYPOINT ["/entrypoint.sh"]
