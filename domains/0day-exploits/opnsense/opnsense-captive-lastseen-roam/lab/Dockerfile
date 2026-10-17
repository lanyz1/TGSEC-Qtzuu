FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    LABEL=opnsense-captive-lastseen-roam \
    WITNESS=OPNSENSE-CAPTIVE-LASTSEEN-ROAM-WITNESS

WORKDIR /lab

RUN mkdir -p \
        /oracle \
        /etc/rc.conf.d \
        /var/db/hostwatch \
        /usr/local/opnsense/site-python \
        /usr/local/opnsense/scripts/interfaces \
        /usr/local/opnsense/scripts/captiveportal/lib \
    && printf '%s\n' 'hostwatch_enable="YES"' > /etc/rc.conf.d/hostwatch \
    && printf '%s\n' \
        "import json" \
        "dumps = json.dumps" \
        "loads = json.loads" \
        > /usr/local/lib/python3.12/site-packages/ujson.py

COPY lab/pin/list_hosts.py /usr/local/opnsense/scripts/interfaces/list_hosts.py
COPY lab/pin/cp-background-process.py /usr/local/opnsense/scripts/captiveportal/cp-background-process.py
COPY lab/pin/lib/arp.py /usr/local/opnsense/scripts/captiveportal/lib/arp.py
COPY lab/pin/lib/__init__.py /usr/local/opnsense/scripts/captiveportal/lib/__init__.py
COPY lab/pin /lab/pin
COPY poc.py /lab/poc.py

RUN chmod 0755 /usr/local/opnsense/scripts/interfaces/list_hosts.py /lab/poc.py

EXPOSE 18820

CMD ["python3", "-c", "import socket,time;s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(('0.0.0.0',18820));s.listen(1);time.sleep(10**9)"]
