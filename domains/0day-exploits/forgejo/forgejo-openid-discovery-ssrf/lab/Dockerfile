FROM python:3.12-slim

COPY poc.py /poc.py

ENV PYTHONUNBUFFERED=1 \
    BIND_HOST=127.0.0.1 \
    BIND_PORT=18080 \
    HITS_PATH=/tmp/forgejo-openid-discovery-hits.jsonl \
    WITNESS=FORGEJO-OPENID-DISCOVERY-WITNESS

CMD ["python3", "/poc.py", "--oracle"]
