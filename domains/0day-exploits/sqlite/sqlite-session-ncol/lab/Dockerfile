FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive \
    ASAN_OPTIONS=detect_leaks=0:abort_on_error=1:halt_on_error=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        curl \
        python3 \
        unzip \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src

# Pin: SQLite 3.53.4 / Git b09c88c14082339b66c7b7158d609a771e64ca69
RUN curl -fsSL --retry 5 --retry-delay 3 \
        -o /tmp/sqlite-src-3530400.zip \
        https://www.sqlite.org/2026/sqlite-src-3530400.zip \
    && unzip -q /tmp/sqlite-src-3530400.zip -d /src \
    && rm /tmp/sqlite-src-3530400.zip \
    && test -d /src/sqlite-src-3530400

WORKDIR /src/sqlite-src-3530400

RUN ./configure \
    && make -j"$(nproc)" sqlite3.c \
    && test -f sqlite3.c \
    && test -f sqlite3.h

WORKDIR /src

COPY poc.c health.py /src/

RUN cc -O1 -g -fsanitize=address -fno-omit-frame-pointer \
        -I/src/sqlite-src-3530400 \
        -DSQLITE_ENABLE_SESSION \
        -DSQLITE_ENABLE_PREUPDATE_HOOK \
        -o /usr/local/bin/sqlite-session-ncol \
        /src/poc.c /src/sqlite-src-3530400/sqlite3.c \
        -lm -lpthread -ldl \
    && install -m 0755 /src/health.py /usr/local/bin/health.py \
    && /usr/local/bin/sqlite-session-ncol version

EXPOSE 18900

CMD ["python3", "/usr/local/bin/health.py"]
