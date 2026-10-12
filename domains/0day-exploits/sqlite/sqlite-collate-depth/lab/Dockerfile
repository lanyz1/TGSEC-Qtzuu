FROM debian:bookworm-slim AS build

ENV DEBIAN_FRONTEND=noninteractive \
    PIN_TAG=version-3.53.4 \
    PIN_GIT=b09c88c14082339b66c7b7158d609a771e64ca69 \
    PIN_SOURCE_ID="2026-07-24 19:02:57 bf7c7f30031888f4e796e429ab3978879485813aaca6f641c7b33e4e09459bcc" \
    SRC_ZIP_URL=https://www.sqlite.org/2026/sqlite-src-3530400.zip

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        curl \
        git \
        tcl \
        unzip \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src

RUN set -eux; \
    if curl -fsSL -o /tmp/sqlite-src.zip "${SRC_ZIP_URL}"; then \
        unzip -q /tmp/sqlite-src.zip -d /src; \
        mv /src/sqlite-src-3530400 /src/sqlite; \
        rm -f /tmp/sqlite-src.zip; \
    else \
        git clone --depth 1 --branch "${PIN_TAG}" https://github.com/sqlite/sqlite.git /src/sqlite; \
    fi

WORKDIR /src/sqlite

RUN CFLAGS="-fsanitize=address -g -O1 -fno-omit-frame-pointer" \
    LDFLAGS="-fsanitize=address" \
    ./configure --disable-tcl \
    && make -j"$(nproc)" sqlite3 \
    && install -m 0755 sqlite3 /usr/local/bin/sqlite3

ENV ASAN_OPTIONS=detect_leaks=0:abort_on_error=1:halt_on_error=1

RUN sid="$(/usr/local/bin/sqlite3 -batch -noheader :memory: "SELECT sqlite_source_id();")" \
    && ver="$(/usr/local/bin/sqlite3 -batch -noheader :memory: "SELECT sqlite_version();")" \
    && echo "sqlite_version=${ver}" \
    && echo "sqlite_source_id=${sid}" \
    && test "${ver}" = "3.53.4" \
    && test "${sid}" = "${PIN_SOURCE_ID}"

FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive \
    ASAN_OPTIONS=detect_leaks=0:abort_on_error=1:halt_on_error=1 \
    PIN_SOURCE_ID="2026-07-24 19:02:57 bf7c7f30031888f4e796e429ab3978879485813aaca6f641c7b33e4e09459bcc"

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        libasan8 \
        python3 \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /work

COPY --from=build /usr/local/bin/sqlite3 /usr/local/bin/sqlite3

WORKDIR /work
EXPOSE 18800

CMD ["python3", "-m", "http.server", "18800", "--bind", "0.0.0.0"]
