FROM postgres:18.6

USER root
RUN apt-get update \
    && apt-get install -y --no-install-recommends python3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /lab
COPY stub.py /lab/stub.py

ENV PYTHONUNBUFFERED=1 \
    BIND_HOST=0.0.0.0 \
    BIND_PORT=5432 \
    WITNESS=POSTGRES-BASEBACKUP-SYMLINK-WITNESS \
    ORACLE_DIR=/work/oracle \
    SERVER_VERSION=18.6

EXPOSE 5432
ENTRYPOINT ["python3", "/lab/stub.py"]
