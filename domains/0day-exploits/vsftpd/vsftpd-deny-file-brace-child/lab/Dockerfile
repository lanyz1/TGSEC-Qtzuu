FROM debian:bookworm-slim AS build

ENV DEBIAN_FRONTEND=noninteractive

# Official vsftpd 3.0.5. SHA-256 26b602ae454b0ba6d99ef44a09b6b9e0dfa7f67228106736df1f278c70bc91d3
# Stock builddefs.h: #undef VSF_BUILD_SSL. Do not install distro vsftpd.

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        libcrypt-dev \
        libpam0g-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src

COPY vsftpd-3.0.5.tar.gz /src/vsftpd-3.0.5.tar.gz

RUN echo "26b602ae454b0ba6d99ef44a09b6b9e0dfa7f67228106736df1f278c70bc91d3  vsftpd-3.0.5.tar.gz" \
        | sha256sum -c - \
    && tar -xzf vsftpd-3.0.5.tar.gz \
    && test -f vsftpd-3.0.5/vsftpver.h \
    && grep -q 'VSF_VERSION "3.0.5"' vsftpd-3.0.5/vsftpver.h \
    && grep -q '#undef VSF_BUILD_SSL' vsftpd-3.0.5/builddefs.h \
    && grep -q '#define VSF_BUILD_PAM' vsftpd-3.0.5/builddefs.h \
    && sed -i 's/-Werror//g' vsftpd-3.0.5/Makefile \
    && make -C vsftpd-3.0.5 LIBS="-lpam -lcrypt -ldl" \
    && test -x vsftpd-3.0.5/vsftpd \
    && install -d /usr/local/sbin \
    && install -m 0755 vsftpd-3.0.5/vsftpd /usr/local/sbin/vsftpd \
    && /usr/local/sbin/vsftpd -v

FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        libpam0g \
        libcrypt1 \
    && rm -rf /var/lib/apt/lists/* \
    && if ! id nobody >/dev/null 2>&1; then \
         useradd --system --no-create-home --home-dir /nonexistent \
           --shell /usr/sbin/nologin nobody; \
       fi \
    && if ! id ftp >/dev/null 2>&1; then \
         useradd --system --home-dir /var/ftp --shell /usr/sbin/nologin \
           --no-create-home ftp; \
       fi \
    && mkdir -p /usr/share/empty /var/ftp/.private /var/ftp/dir \
    && chown root:root /usr/share/empty /var/ftp \
    && chmod 755 /usr/share/empty /var/ftp /var/ftp/.private /var/ftp/dir \
    && printf '%s\n' "VSFTPD-DENY-FILE-BRACE-CHILD-WITNESS" > /var/ftp/.private/secret \
    && printf 'DIRDOT-%s\n' "VSFTPD-DENY-FILE-BRACE-CHILD-WITNESS" > /var/ftp/dir/.private \
    && printf '%s\n' "MP3-CLOSED-NOT-WITNESS" > /var/ftp/song.mp3 \
    && chmod 0644 /var/ftp/.private/secret /var/ftp/dir/.private /var/ftp/song.mp3 \
    && chown root:root /var/ftp/.private/secret /var/ftp/dir/.private /var/ftp/song.mp3

COPY --from=build /usr/local/sbin/vsftpd /usr/local/sbin/vsftpd
COPY vsftpd.conf /etc/vsftpd.conf

EXPOSE 21 18711-18718

CMD ["/usr/local/sbin/vsftpd", "/etc/vsftpd.conf"]
