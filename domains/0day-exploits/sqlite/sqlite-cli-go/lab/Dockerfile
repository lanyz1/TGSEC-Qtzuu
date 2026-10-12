FROM debian:bookworm-slim AS build

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        curl \
        unzip \
    && rm -rf /var/lib/apt/lists/*

ARG SQLITE_SRC_URL=https://www.sqlite.org/2026/sqlite-src-3530400.zip
ARG SQLITE_SRC_DIR=sqlite-src-3530400
ARG SQLITE_SOURCE_ID=2026-07-24 19:02:57 bf7c7f30031888f4e796e429ab3978879485813aaca6f641c7b33e4e09459bcc

WORKDIR /src

RUN curl -fsSL "${SQLITE_SRC_URL}" -o sqlite-src.zip \
    && unzip -q sqlite-src.zip \
    && test -f "${SQLITE_SRC_DIR}/VERSION" \
    && test "$(tr -d '[:space:]' < "${SQLITE_SRC_DIR}/VERSION")" = "3.53.4"

WORKDIR /src/sqlite-src-3530400

# Default CLI (no --safe). Readline is unused; the lab feeds stdin.
RUN ./configure --prefix=/usr/local --disable-readline \
    && make -j"$(nproc)" sqlite3 \
    && test -x ./sqlite3 \
    && ./sqlite3 --version \
    && ./sqlite3 --version | grep -F "3.53.4" \
    && ./sqlite3 --version | grep -F "bf7c7f30031888f4e796e429ab3978879485813aaca6f641c7b33e4e09459bcc" \
    && install -m 0755 sqlite3 /usr/local/bin/sqlite3

COPY ready.c /tmp/ready.c
RUN gcc -O2 -o /usr/local/bin/ready /tmp/ready.c

FROM debian:bookworm-slim

COPY --from=build /usr/local/bin/sqlite3 /usr/local/bin/sqlite3
COPY --from=build /usr/local/bin/ready /usr/local/bin/ready

WORKDIR /work
EXPOSE 18920

CMD ["/usr/local/bin/ready"]
