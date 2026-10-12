FROM debian:bookworm-slim AS build

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        curl \
        python3 \
        tcl \
        unzip \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src

# Canonical 3.53.4 source zip (SHA3-256 from sqlite.org/download.html).
ARG SQLITE_SRC_URL=https://www.sqlite.org/2026/sqlite-src-3530400.zip
ARG SQLITE_SRC_SHA3=b834d474b9b393d85a9e3ee4cc11f1329e007e9376a424ee740796f5c4bda3a8

RUN curl -fsSL -o sqlite-src-3530400.zip "${SQLITE_SRC_URL}" \
    && python3 -c "import hashlib, pathlib, sys; \
p=pathlib.Path('sqlite-src-3530400.zip'); \
h=hashlib.sha3_256(p.read_bytes()).hexdigest(); \
want=sys.argv[1]; \
print('sha3-256', h); \
raise SystemExit(0 if h==want else 1)" "${SQLITE_SRC_SHA3}" \
    && unzip -q sqlite-src-3530400.zip \
    && rm sqlite-src-3530400.zip

WORKDIR /src/sqlite-src-3530400

# FTS5 is off unless --enable-fts5. ASan + -O1 matches the public forum trigger.
RUN CFLAGS="-O1 -g -fno-omit-frame-pointer -fsanitize=address -DSQLITE_ENABLE_FTS5" \
    LDFLAGS="-fsanitize=address" \
    ./configure --enable-fts5 \
    && make sqlite3 \
    && install -m 0755 sqlite3 /usr/local/bin/sqlite3 \
    && /usr/local/bin/sqlite3 :memory: "SELECT sqlite_version(); SELECT sqlite_source_id();" \
    && /usr/local/bin/sqlite3 :memory: "CREATE VIRTUAL TABLE t USING fts5(a);"

FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive \
    ASAN_OPTIONS=detect_leaks=0:abort_on_error=1:halt_on_error=1:allocator_may_return_null=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        libasan8 \
        python3 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /usr/local/bin/sqlite3 /usr/local/bin/sqlite3
COPY harness.py /opt/lab/harness.py

EXPOSE 8080
WORKDIR /tmp

CMD ["python3", "/opt/lab/harness.py"]
