FROM python:3.12-slim-bookworm

ENV PYTHONUNBUFFERED=1 \
    LANG=C.UTF-8 \
    LAB_BIND_HOST=0.0.0.0 \
    LAB_BIND_PORT=19191 \
    LAB_CONNECT_HOST=127.0.0.1 \
    LAB_CERT_CN=pfsense-controller.lab

RUN apt-get update \
    && apt-get install -y --no-install-recommends openssl ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir "httpx>=0.27,<0.29"

WORKDIR /lab
COPY poc.py /lab/poc.py
CMD ["sleep", "infinity"]
