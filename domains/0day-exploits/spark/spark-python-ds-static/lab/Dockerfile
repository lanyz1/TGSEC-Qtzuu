FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app
COPY gadget_server.py /app/gadget_server.py

RUN mkdir -p /oracle /work/sessions \
    && chmod 0755 /app/gadget_server.py

EXPOSE 18970
CMD ["python3", "-u", "/app/gadget_server.py"]
