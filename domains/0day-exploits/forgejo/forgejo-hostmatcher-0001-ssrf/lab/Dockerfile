# Sidecar oracle for forgejo-hostmatcher-0001-ssrf. Full stack: docker-compose.yml
FROM python:3.12-alpine

RUN apk add --no-cache iproute2

COPY oracle.py /oracle.py

ENV PYTHONUNBUFFERED=1 \
    BIND_HOST=0.0.0.0 \
    BIND_PORT=8080 \
    WITNESS=FORGEJO-HOSTMATCHER-0001-WITNESS

CMD ["python3", "/oracle.py"]
