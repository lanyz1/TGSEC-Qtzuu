FROM python:3.13-slim

ENV PYTHONUNBUFFERED=1 \
    LANG=C.UTF-8 \
    BIND_HOST=0.0.0.0 \
    CONTROL_PORT=3306 \
    TRAVERSAL_PORT=3307 \
    WITNESS=MYSQL-BINLOG-RAW-WITNESS

WORKDIR /lab
COPY stub.py /lab/stub.py
CMD ["python3", "/lab/stub.py"]
