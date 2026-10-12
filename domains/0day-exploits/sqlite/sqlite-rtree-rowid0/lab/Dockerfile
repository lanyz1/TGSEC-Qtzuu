FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive \
    ASAN_OPTIONS=detect_leaks=0:abort_on_error=1:halt_on_error=1:print_stacktrace=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        curl \
        git \
        python3 \
        tcl \
        unzip \
    && rm -rf /var/lib/apt/lists/*

# Pin: SQLite 3.53.4 / Git b09c88c14082339b66c7b7158d609a771e64ca69
WORKDIR /src
RUN curl -fsSL -o sqlite.zip https://www.sqlite.org/2026/sqlite-src-3530400.zip \
    && unzip -q sqlite.zip \
    && mv sqlite-src-3530400 sqlite \
    && rm -f sqlite.zip \
    && test -f sqlite/VERSION \
    && grep -q '^3.53.4$' sqlite/VERSION

WORKDIR /src/sqlite
RUN ./configure --enable-all \
    && make -j"$(nproc)" sqlite3.c sqlite3.h \
    && test -f sqlite3.c \
    && test -f sqlite3.h

COPY harness.c /src/harness.c

RUN mkdir -p /opt/lab \
    && gcc -O0 -g -fno-omit-frame-pointer -fsanitize=address \
        -DSQLITE_ENABLE_RTREE=1 \
        -DSQLITE_THREADSAFE=0 \
        -DSQLITE_OMIT_LOAD_EXTENSION \
        -DSQLITE_PRIVATE= \
        -I/src/sqlite \
        -o /opt/lab/harness /src/harness.c /src/sqlite/sqlite3.c \
        -lm \
    && /opt/lab/harness --version

WORKDIR /work
EXPOSE 18890
CMD ["python3", "-m", "http.server", "18890", "--bind", "0.0.0.0"]
