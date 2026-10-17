FROM python:3.12-slim-bookworm

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    WITNESS=PFSENSE-API-ENROLL-AUTOADD-WITNESS \
    SSH_BIND=0.0.0.0 \
    SSH_PORT=19111 \
    SSH_USER=admin \
    SSH_PASS=sshsecret

RUN pip install --no-cache-dir "paramiko>=3.4,<4"

WORKDIR /lab
COPY poc.py /lab/poc.py

EXPOSE 19111
CMD ["python3", "/lab/poc.py", "--server"]
