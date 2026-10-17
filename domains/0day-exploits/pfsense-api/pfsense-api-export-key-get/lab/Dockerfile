FROM python:3.12-alpine

WORKDIR /lab
COPY poc.py /lab/poc.py
COPY openapi-export-key.yml /lab/openapi-export-key.yml
COPY generated_kwargs.py /lab/generated_kwargs.py

ENV PYTHONUNBUFFERED=1 \
    WITNESS=PFSENSE-API-EXPORT-KEY-GET-WITNESS \
    MOCK_BIND=0.0.0.0 \
    MOCK_PORT=19141

CMD ["python3", "/lab/poc.py", "--mock"]
