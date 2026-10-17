FROM debian:bookworm-slim AS build

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        libcrypt-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src

# Pin: official vsftpd 3.0.5 SHA-256 26b602ae454b0ba6d99ef44a09b6b9e0dfa7f67228106736df1f278c70bc91d3
COPY vsftpd-3.0.5.tar.gz /src/vsftpd-3.0.5.tar.gz

RUN echo "26b602ae454b0ba6d99ef44a09b6b9e0dfa7f67228106736df1f278c70bc91d3  vsftpd-3.0.5.tar.gz" \
        | sha256sum -c - \
    && tar -xzf vsftpd-3.0.5.tar.gz \
    && test -f vsftpd-3.0.5/vsftpver.h \
    && grep -q 'VSF_VERSION "3.0.5"' vsftpd-3.0.5/vsftpver.h \
    && grep -n 'cmds_denied' vsftpd-3.0.5/postlogin.c \
    && grep -n 'XRMD' vsftpd-3.0.5/postlogin.c

WORKDIR /src/vsftpd-3.0.5

# Official Makefile uses -Werror; gcc 12 on bookworm fails the pin without it.
# Leave SSL/PAM/libcap headers to dummyinc so this is not a distro package.
RUN sed -i 's/ -Werror / /' Makefile \
    && make -j"$(nproc)" LIBS="-lcrypt" \
    && install -d /usr/local/sbin \
    && install -m 0755 vsftpd /usr/local/sbin/vsftpd \
    && /usr/local/sbin/vsftpd -v

FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        libcrypt1 \
    && rm -rf /var/lib/apt/lists/* \
    && if ! id nobody >/dev/null 2>&1; then \
         useradd --system --no-create-home --shell /usr/sbin/nologin nobody; \
       fi \
    && groupadd -r ftp \
    && useradd -r -g ftp -d /var/ftp -s /usr/sbin/nologin ftp \
    && mkdir -p /var/ftp/incoming /usr/share/empty \
    && chown root:root /var/ftp /usr/share/empty \
    && chmod 755 /var/ftp /usr/share/empty \
    && chown ftp:ftp /var/ftp/incoming \
    && chmod 0775 /var/ftp/incoming

COPY --from=build /usr/local/sbin/vsftpd /usr/local/sbin/vsftpd
COPY vsftpd.conf /etc/vsftpd.conf

RUN chown root:root /etc/vsftpd.conf \
    && chmod 644 /etc/vsftpd.conf \
    && /usr/local/sbin/vsftpd -v

EXPOSE 21

CMD ["/usr/local/sbin/vsftpd", "/etc/vsftpd.conf"]
