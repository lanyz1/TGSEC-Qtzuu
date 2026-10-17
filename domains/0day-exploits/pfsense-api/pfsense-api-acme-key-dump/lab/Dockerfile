FROM python:3.12-alpine
WORKDIR /lab
COPY poc.py /lab/poc.py
ENV PYTHONUNBUFFERED=1 \
    LAB_ROLE=mock \
    LAB_BIND=0.0.0.0 \
    LAB_PORT=19151 \
    WITNESS=PFSENSE-API-ACME-KEY-DUMP-WITNESS
EXPOSE 19151
CMD ["python3", "/lab/poc.py", "--mock"]
