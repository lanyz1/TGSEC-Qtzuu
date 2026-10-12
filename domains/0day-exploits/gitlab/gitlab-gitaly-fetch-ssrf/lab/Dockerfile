FROM python:3.12-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends git iptables iproute2 procps \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /lab
COPY dns_server.py catcher.py /lab/
RUN chmod +x /lab/dns_server.py /lab/catcher.py

ENV PYTHONUNBUFFERED=1 \
    WITNESS=GITLAB-GITALY-FETCH-SSRF-WITNESS \
    GIT_ROOT=/git \
    SHARED_DIR=/shared \
    LOG_DIR=/logs \
    BIND_HOST=0.0.0.0 \
    BIND_PORT=18080 \
    PUBLIC_IP=1.1.1.1 \
    REBIND_IP=127.0.0.1 \
    GHE_NAME=ghe.lab

CMD ["python3", "/lab/catcher.py"]
