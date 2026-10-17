FROM php:8.3-cli-bookworm

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        iproute2 \
        openssl \
        openvpn \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /oracle /lab/pki /lab/pin

WORKDIR /lab

COPY pin/ /lab/pin/
COPY gadget.php /lab/gadget.php
COPY write-witness.sh /oracle/write-witness.sh

RUN chmod 0755 /oracle/write-witness.sh \
    && openssl req -x509 -newkey rsa:2048 -sha256 -nodes \
        -keyout /lab/pki/key.pem \
        -out /lab/pki/cert.pem \
        -days 3 \
        -subj "/CN=lab-openvpn"

EXPOSE 18820

CMD ["php", "-S", "0.0.0.0:18820", "-t", "/lab", "/lab/gadget.php"]
