FROM python:3.12-alpine

WORKDIR /lab
COPY dns_server.py catcher.py /lab/

ENV PYTHONUNBUFFERED=1 \
    WITNESS=GITLAB-GITEA-IMPORT-SSRF-WITNESS \
    GITEA_NAME=gitea.lab \
    PUBLIC_A=1.1.1.1 \
    LOOPBACK_A=127.0.0.1 \
    REBIND_MODE=pairs \
    FORWARD_DNS=1.1.1.1 \
    TLS_CERT=/certs/gitea.crt \
    CATCHER_TLS_KEY=/certs/gitea.key

CMD ["python3", "/lab/catcher.py"]
