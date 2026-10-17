FROM --platform=linux/amd64 apache/openmeetings:min-9.1.0

USER root
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends openjdk-21-jre-headless \
    && rm -rf /var/lib/apt/lists/*

COPY entrypoint.sh /opt/lab-entrypoint.sh
RUN chmod a+x /opt/lab-entrypoint.sh

ENTRYPOINT ["bash", "/opt/lab-entrypoint.sh"]
