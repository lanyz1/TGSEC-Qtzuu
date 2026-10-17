FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive \
    VSFTPD_TARBALL_SHA256=26b602ae454b0ba6d99ef44a09b6b9e0dfa7f67228106736df1f278c70bc91d3

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        gcc \
        libcap-dev \
        libpam0g-dev \
        libssl-dev \
        make \
        openssl \
        wget \
    && rm -rf /var/lib/apt/lists/*

# Official pin; staged COPY is the offline fallback (run.sh places the tarball).
COPY vsftpd-3.0.5.tar.gz /tmp/vsftpd-staged.tar.gz
RUN wget -q -O /tmp/vsftpd-3.0.5.tar.gz \
        https://security.appspot.com/downloads/vsftpd-3.0.5.tar.gz \
    || true \
    && if ! echo "${VSFTPD_TARBALL_SHA256}  /tmp/vsftpd-3.0.5.tar.gz" | sha256sum -c -; then \
        cp /tmp/vsftpd-staged.tar.gz /tmp/vsftpd-3.0.5.tar.gz; \
        echo "${VSFTPD_TARBALL_SHA256}  /tmp/vsftpd-3.0.5.tar.gz" | sha256sum -c -; \
    fi \
    && mkdir -p /build \
    && tar -xzf /tmp/vsftpd-3.0.5.tar.gz -C /build \
    && test -f /build/vsftpd-3.0.5/vsftpver.h \
    && grep -q 'VSF_VERSION "3.0.5"' /build/vsftpd-3.0.5/vsftpver.h

WORKDIR /build/vsftpd-3.0.5

# Stock tarball has #undef VSF_BUILD_SSL; distro FTPS builds define it.
RUN sed -i 's/^#undef VSF_BUILD_SSL/#define VSF_BUILD_SSL/' builddefs.h \
    && grep -q '^#define VSF_BUILD_SSL' builddefs.h \
    && sed -i 's/ -Werror / /' Makefile \
    && sed -i 's/-Wall -W -Wshadow/-Wall -W -Wshadow -Wno-deprecated-declarations/' Makefile \
    && make -j"$(nproc)" \
        LIBS="`./vsf_findlibs.sh` -lpam -lcap -lssl -lcrypto -lcrypt" \
    && install -m 0755 vsftpd /usr/sbin/vsftpd \
    && /usr/sbin/vsftpd -v

RUN mkdir -p /usr/share/empty /var/ftp /etc/ssl/private /var/log \
    && chmod 555 /usr/share/empty \
    && id nobody >/dev/null \
    && if ! id ftp >/dev/null 2>&1; then \
        useradd -d /var/ftp -s /usr/sbin/nologin ftp; \
    fi \
    && chown root:root /var/ftp \
    && chmod 0755 /var/ftp \
    && printf '%s\n' 'VSFTPD-SSL-DATA-ANY-TICKET-WITNESS' > /var/ftp/secret.txt \
    && chown root:root /var/ftp/secret.txt \
    && chmod 0644 /var/ftp/secret.txt \
    && openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
        -keyout /tmp/vsftpd.key \
        -out /tmp/vsftpd.crt \
        -subj '/CN=vsftpd' \
    && cat /tmp/vsftpd.crt /tmp/vsftpd.key > /etc/ssl/private/vsftpd.pem \
    && chmod 600 /etc/ssl/private/vsftpd.pem \
    && rm -f /tmp/vsftpd.key /tmp/vsftpd.crt /tmp/vsftpd-3.0.5.tar.gz /tmp/vsftpd-staged.tar.gz

COPY vsftpd.conf /etc/vsftpd.conf

EXPOSE 21 18701-18708
CMD ["/usr/sbin/vsftpd", "/etc/vsftpd.conf"]
