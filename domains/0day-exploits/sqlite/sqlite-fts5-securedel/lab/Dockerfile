FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive \
    ASAN_OPTIONS=detect_leaks=0:abort_on_error=1:halt_on_error=1:print_stats=0

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        python3 \
        unzip \
        wget \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src

# Canonical 3.53.4 source drop. Pin is also Git b09c88c14082339b66c7b7158d609a771e64ca69.
RUN wget -q -O sqlite-src-3530400.zip \
        https://www.sqlite.org/2026/sqlite-src-3530400.zip \
    && unzip -q sqlite-src-3530400.zip \
    && rm sqlite-src-3530400.zip

WORKDIR /src/sqlite-src-3530400

RUN CFLAGS="-g -O1 -fno-omit-frame-pointer -fsanitize=address -DSQLITE_ENABLE_FTS5" \
    LDFLAGS="-fsanitize=address" \
    ./configure --disable-tcl \
    && make -j"$(nproc)" sqlite3 \
    && install -m 0755 sqlite3 /usr/local/bin/sqlite3 \
    && /usr/local/bin/sqlite3 :memory: "SELECT sqlite_version(); SELECT sqlite_source_id();"

WORKDIR /work
EXPOSE 18860

CMD ["python3", "-m", "http.server", "18860", "--bind", "0.0.0.0"]
