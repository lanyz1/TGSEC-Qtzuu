FROM python:3.13-slim

RUN useradd --create-home --uid 1000 spark \
    && mkdir -p /tmp/spark-events /secret \
    && chown -R spark:spark /tmp/spark-events /secret

COPY stub.py /lab/stub.py
RUN chown spark:spark /lab/stub.py

USER spark
WORKDIR /lab

ENV PYTHONUNBUFFERED=1 \
    BIND_HOST=0.0.0.0 \
    BIND_PORT=18080 \
    LOG_DIR=/tmp/spark-events \
    SECRET_PATH=/secret/host-secret \
    APP_ID=app-2026-0001 \
    WITNESS=SPARK-HISTORY-ZIP-SYMLINK-WITNESS

EXPOSE 18080
CMD ["python3", "/lab/stub.py"]
