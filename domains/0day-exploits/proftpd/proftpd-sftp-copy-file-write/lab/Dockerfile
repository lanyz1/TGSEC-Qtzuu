FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        git \
        libssl-dev \
        openssh-client \
        perl \
        pkg-config \
        zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 --branch v1.3.9d https://github.com/proftpd/proftpd.git /build/proftpd
WORKDIR /build/proftpd

RUN grep -F 'PROFTPD_VERSION_TEXT' include/version.h | grep -F '1.3.9d' \
    && ./configure \
        --prefix=/usr/local \
        --sysconfdir=/etc/proftpd \
        --localstatedir=/var/run/proftpd \
        --enable-openssl \
        --disable-auth-pam \
        --with-modules=mod_sftp \
        --with-includes=/usr/include \
        --with-libraries=/usr/lib/$(dpkg-architecture -qDEB_HOST_MULTIARCH) \
    && make -j"$(nproc)" \
    && make install \
    && proftpd -v

RUN mkdir -p /etc/proftpd /var/run/proftpd /var/log/proftpd \
        /home/labuser/readable /home/labuser/nowrite \
    && groupadd -g 1000 labuser \
    && useradd -u 1000 -g 1000 -d /home/labuser -s /bin/false labuser \
    && printf '%s\n' 'PROFTPD-SFTP-COPY-FILE-WRITE-WITNESS' \
        > /home/labuser/readable/src.txt \
    && chmod 0755 /home/labuser /home/labuser/readable /home/labuser/nowrite \
    && chmod 0644 /home/labuser/readable/src.txt \
    && chown -R labuser:labuser /home/labuser \
    && ssh-keygen -m PEM -t rsa -b 2048 -f /etc/proftpd/ssh_host_rsa_key -N "" -q \
    && openssl genpkey -algorithm ED25519 -out /etc/proftpd/ssh_host_ed25519_key \
    && chmod 0600 /etc/proftpd/ssh_host_ed25519_key /etc/proftpd/ssh_host_rsa_key \
    && FTPASSWD="$(command -v ftpasswd || echo /build/proftpd/contrib/ftpasswd)" \
    && printf '%s\n' labpass | "${FTPASSWD}" \
        --passwd --sha512 --stdin \
        --name=labuser --uid=1000 --gid=1000 \
        --home=/home/labuser --shell=/bin/false \
        --file=/etc/proftpd/ftpd.passwd \
    && "${FTPASSWD}" \
        --group \
        --name=labuser --gid=1000 --member=labuser \
        --file=/etc/proftpd/ftpd.group \
    && chmod 0440 /etc/proftpd/ftpd.passwd /etc/proftpd/ftpd.group \
    && chown root:root /etc/proftpd/ftpd.passwd /etc/proftpd/ftpd.group

COPY proftpd.conf /etc/proftpd/proftpd.conf
COPY entrypoint.sh /entrypoint.sh
RUN chmod 0755 /entrypoint.sh \
    && proftpd -t -c /etc/proftpd/proftpd.conf

EXPOSE 2222
CMD ["/entrypoint.sh"]
