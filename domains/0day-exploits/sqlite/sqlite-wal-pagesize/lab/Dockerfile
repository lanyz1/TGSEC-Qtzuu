FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        curl \
        python3 \
        tcl \
        unzip \
    && rm -rf /var/lib/apt/lists/*

# Canonical source zip for 3.53.4 (Fossil SOURCE_ID 2026-07-24).
ARG SQLITE_ZIP_URL=https://www.sqlite.org/2026/sqlite-src-3530400.zip
WORKDIR /src
RUN curl -fsSL -o /tmp/sqlite-src.zip "${SQLITE_ZIP_URL}" \
    && unzip -q /tmp/sqlite-src.zip -d /src \
    && rm -f /tmp/sqlite-src.zip \
    && test -d /src/sqlite-src-3530400 \
    && grep -qx '3.53.4' /src/sqlite-src-3530400/VERSION

WORKDIR /src/sqlite-src-3530400
RUN ./configure --prefix=/usr/local --disable-readline \
    && make -j"$(nproc)" sqlite3.c sqlite3 \
    && gcc -O2 -g -fPIC -shared -o /usr/local/lib/libsqlite3.so sqlite3.c -ldl -lpthread -lm \
    && install -m 0755 sqlite3 /usr/local/bin/sqlite3 \
    && install -m 0644 sqlite3.h /usr/local/include/sqlite3.h \
    && ldconfig \
    && /usr/local/bin/sqlite3 -version

WORKDIR /work
EXPOSE 18830
CMD ["python3", "-m", "http.server", "18830", "--bind", "0.0.0.0"]
