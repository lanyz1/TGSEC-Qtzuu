FROM python:3.12-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends iproute2 procps \
    && rm -rf /var/lib/apt/lists/*

COPY catcher.py /catcher.py

ENV PYTHONUNBUFFERED=1 \
    BIND_HOST=0.0.0.1 \
    BIND_PORT=18080 \
    WITNESS=GITLAB-WEBHOOK-0NET-SSRF-WITNESS

CMD ["python3", "/catcher.py"]
