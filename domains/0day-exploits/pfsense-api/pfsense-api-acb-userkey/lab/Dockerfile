FROM python:3.12-alpine

WORKDIR /lab
COPY poc.py /lab/poc.py

ENV PYTHONUNBUFFERED=1 \
    WITNESS=PFSENSE-API-ACB-USERKEY-WITNESS \
    MOCK_BIND=0.0.0.0 \
    MOCK_PORT=8080

EXPOSE 8080

CMD ["python3", "/lab/poc.py", "--mock"]
