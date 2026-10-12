FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends g++ ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /lab
COPY gadget.cpp /lab/gadget.cpp
COPY pin-src /lab/pin-src

RUN g++ -O2 -std=c++17 -Wall -Wextra -o /usr/local/bin/h3-mtls-gadget /lab/gadget.cpp \
    && test -s /lab/pin-src/hiocrypto.h \
    && test -s /lab/pin-src/quicstream.h

EXPOSE 19200
CMD ["/usr/local/bin/h3-mtls-gadget"]
