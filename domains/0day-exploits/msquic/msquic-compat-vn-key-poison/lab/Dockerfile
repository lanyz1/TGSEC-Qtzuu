FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive \
    GIT_TERMINAL_PROMPT=0 \
    LANG=C.UTF-8

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        cmake \
        git \
        openssl \
        patch \
        perl \
        python3 \
        pkg-config \
    && rm -rf /var/lib/apt/lists/*

ARG MSQUIC_PIN=a01333cf7c2659cce0ff03ef3f21e1ff15bb5b83
WORKDIR /src
RUN set -eux; \
    ok=0; \
    for attempt in 1 2 3; do \
      if git clone --depth 1 --branch v2.6.1 https://github.com/microsoft/msquic.git; then \
        ok=1; \
        break; \
      fi; \
      rm -rf msquic; \
      sleep 8; \
    done; \
    test "$ok" = 1; \
    cd msquic; \
    HEAD="$(git rev-parse HEAD)"; \
    case "$HEAD" in \
      "${MSQUIC_PIN}"*|a01333cf*) ;; \
      *) \
        git fetch --depth 1 origin "${MSQUIC_PIN}"; \
        git checkout "${MSQUIC_PIN}"; \
        ;; \
    esac; \
    git rev-parse HEAD; \
    git submodule update --init --depth 1 submodules/openssl

WORKDIR /src/msquic/build
RUN cmake -G "Unix Makefiles" \
        -DCMAKE_BUILD_TYPE=Release \
        -DQUIC_BUILD_TOOLS=ON \
        -DQUIC_BUILD_TEST=OFF \
        -DQUIC_BUILD_PERF=OFF \
        -DQUIC_TLS_LIB=openssl \
        -DQUIC_ENABLE_LOGGING=OFF \
        ..

COPY sample.patch /tmp/sample.patch
RUN set -eux; \
    cd /src/msquic; \
    git apply /tmp/sample.patch; \
    cmake --build /src/msquic/build --target quicsample -j"$(nproc)"; \
    mkdir -p /opt/msquic; \
    find /src/msquic/build -type f \( -name quicsample -o -name 'libmsquic.so*' \) -exec cp -a {} /opt/msquic/ \; ; \
    test -x /opt/msquic/quicsample; \
    /opt/msquic/quicsample -help >/dev/null || true

ENV PATH="/opt/msquic:${PATH}" \
    LD_LIBRARY_PATH="/opt/msquic" \
    QUICSAMPLE="/opt/msquic/quicsample"

RUN mkdir -p /certs \
    && openssl req -nodes -new -x509 \
        -keyout /certs/server.key \
        -out /certs/server.cert \
        -subj "/CN=localhost"

WORKDIR /lab
COPY poc.py /lab/poc.py
CMD ["sleep", "infinity"]
