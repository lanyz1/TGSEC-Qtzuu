FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    ORACLE=/oracle

RUN mkdir -p /lab /oracle /sbin

# Pin lockout_handler (opnsense/core 26.7.6 peel a842fe48), unchanged.
COPY lab/lockout_handler /lab/lockout_handler
COPY lab/pfctl /sbin/pfctl
COPY poc.py /lab/poc.py

RUN chmod 0755 /sbin/pfctl /lab/poc.py \
    && chmod 0644 /lab/lockout_handler \
    && test -x /usr/local/bin/python3

WORKDIR /lab
CMD ["sleep", "infinity"]
