FROM debian:bookworm-slim AS build

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        curl \
        tcl \
        unzip \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src

# Canonical 3.53.4 source zip (Fossil SOURCE_ID 2026-07-24 19:02:57 bf7c7f3...).
RUN curl -fsSL -o sqlite-src.zip https://www.sqlite.org/2026/sqlite-src-3530400.zip \
    && unzip -q sqlite-src.zip \
    && rm sqlite-src.zip \
    && srcdir="$(find . -maxdepth 1 -type d -name 'sqlite-src-*' | head -n 1)" \
    && test -n "${srcdir}" \
    && mv "${srcdir}" /src/sqlite

WORKDIR /src/sqlite

RUN CFLAGS="-g -O1 -fno-omit-frame-pointer -fsanitize=address" \
    LDFLAGS="-fsanitize=address" \
    ./configure --disable-readline \
    && make -j"$(nproc)" sqlite3 \
    && ./sqlite3 :memory: "SELECT sqlite_version(); SELECT sqlite_source_id();"

FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive \
    ASAN_OPTIONS=detect_leaks=0:abort_on_error=1:halt_on_error=1 \
    LABEL=sqlite-values-union \
    WITNESS=SQLITE-VALUES-UNION-WITNESS

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        libasan8 \
        python3 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /src/sqlite/sqlite3 /usr/local/bin/sqlite3

EXPOSE 18820

CMD ["python3", "-m", "http.server", "18820", "--bind", "0.0.0.0"]
