FROM debian:bookworm-slim AS build

ENV DEBIAN_FRONTEND=noninteractive \
    SOURCE_ZIP_URL=https://www.sqlite.org/2026/sqlite-src-3530400.zip \
    SOURCE_ZIP_SHA3=b834d474b9b393d85a9e3ee4cc11f1329e007e9376a424ee740796f5c4bda3a8

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        python3 \
        tcl \
        unzip \
        wget \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /tmp

RUN wget -q --tries=4 --timeout=60 -O sqlite-src-3530400.zip "${SOURCE_ZIP_URL}" \
    && python3 -c "\
import hashlib, pathlib, sys; \
h = hashlib.sha3_256(pathlib.Path('sqlite-src-3530400.zip').read_bytes()).hexdigest(); \
want = '${SOURCE_ZIP_SHA3}'; \
sys.exit(0 if h == want else (print('sha3-mismatch', h, 'want', want, file=sys.stderr) or 1))" \
    && unzip -q sqlite-src-3530400.zip \
    && rm -f sqlite-src-3530400.zip

WORKDIR /tmp/sqlite-src-3530400

RUN CFLAGS="-g -O1 -fno-omit-frame-pointer -fsanitize=address" \
    LDFLAGS="-fsanitize=address" \
    ./configure \
    && make -j"$(nproc)" sqlite3 \
    && install -m 0755 sqlite3 /usr/local/bin/sqlite3 \
    && /usr/local/bin/sqlite3 :memory: "SELECT sqlite_version();" \
    && /usr/local/bin/sqlite3 :memory: "SELECT sqlite_source_id();"

FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive \
    ASAN_OPTIONS=detect_leaks=0:abort_on_error=1:halt_on_error=1:print_stacktrace=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        libasan8 \
        python3 \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /opt/lab /work

COPY --from=build /usr/local/bin/sqlite3 /usr/local/bin/sqlite3

RUN printf '%s\n' \
    'from http.server import BaseHTTPRequestHandler, HTTPServer' \
    '' \
    'class Ready(BaseHTTPRequestHandler):' \
    '    def do_GET(self):' \
    '        body = b"ok SQLITE-CTE-NEST-WITNESS\\n"' \
    '        self.send_response(200)' \
    '        self.send_header("Content-Type", "text/plain; charset=utf-8")' \
    '        self.send_header("Content-Length", str(len(body)))' \
    '        self.end_headers()' \
    '        self.wfile.write(body)' \
    '    def log_message(self, fmt, *args):' \
    '        return' \
    '' \
    'HTTPServer(("0.0.0.0", 8080), Ready).serve_forever()' \
    > /opt/lab/ready.py \
    && /usr/local/bin/sqlite3 :memory: "SELECT sqlite_source_id();" \
        | grep -F "2026-07-24 19:02:57 bf7c7f30031888f4e796e429ab3978879485813aaca6f641c7b33e4e09459bcc"

WORKDIR /work
EXPOSE 8080

CMD ["python3", "/opt/lab/ready.py"]
