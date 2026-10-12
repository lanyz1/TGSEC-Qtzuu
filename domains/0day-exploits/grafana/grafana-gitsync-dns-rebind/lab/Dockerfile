FROM python:3.12-alpine

WORKDIR /lab
COPY poc.py /lab/poc.py

ENV PYTHONUNBUFFERED=1 \
    WITNESS=GRAFANA-GITSYNC-DNS-REBIND-WITNESS

CMD ["python3", "/lab/poc.py", "--oracle"]
