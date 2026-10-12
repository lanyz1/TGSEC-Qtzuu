FROM debian:bookworm-slim AS build

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        curl \
        unzip \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src

# Pin SQLite 3.53.4 (Fossil SOURCE_ID 2026-07-24 19:02:57 bf7c7f3003...).
RUN curl -fsSL -o sqlite-src-3530400.zip \
        https://www.sqlite.org/2026/sqlite-src-3530400.zip \
    && unzip -q sqlite-src-3530400.zip \
    && test -d sqlite-src-3530400 \
    && rm sqlite-src-3530400.zip

WORKDIR /src/sqlite-src-3530400

RUN ./configure --prefix=/usr/local \
    && make -j"$(nproc)" sqlite3.c

COPY xfer_auth.c /src/xfer_auth.c

RUN gcc -O2 -DSQLITE_THREADSAFE=1 \
        -o /usr/local/bin/xfer-auth \
        /src/xfer_auth.c sqlite3.c \
        -I. -lpthread -ldl -lm \
    && /usr/local/bin/xfer-auth --once

FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive \
    PORT=18850

COPY --from=build /usr/local/bin/xfer-auth /usr/local/bin/xfer-auth

EXPOSE 18850

CMD ["xfer-auth"]
