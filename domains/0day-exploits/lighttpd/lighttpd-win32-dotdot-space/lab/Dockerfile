FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends gcc libc6-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /lab

COPY gadget.c /lab/gadget.c

RUN gcc -O2 -Wall -Wextra -o /lab/gadget /lab/gadget.c

EXPOSE 19400

CMD ["/lab/gadget"]
