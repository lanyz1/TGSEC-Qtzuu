FROM python:3.13-slim

LABEL lab=spark-connect-copy-local

RUN useradd --uid 185 --create-home --shell /bin/bash spark \
    && mkdir -p /opt/spark/work/artifacts /oracle \
    && chown -R spark:spark /opt/spark /oracle

COPY gadget.py /opt/spark/gadget.py

USER 185
WORKDIR /opt/spark
EXPOSE 18920

CMD ["python3", "/opt/spark/gadget.py"]
