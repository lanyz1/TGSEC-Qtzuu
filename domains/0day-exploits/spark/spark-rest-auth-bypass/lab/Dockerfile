FROM spark:4.2.0

USER root

COPY spark-defaults.conf /opt/spark/conf/spark-defaults.conf
COPY log4j2.properties /opt/spark/conf/log4j2.properties
COPY WitnessMain.java /tmp/WitnessMain.java
COPY start-master.sh /opt/lab/start-master.sh
COPY start-worker.sh /opt/lab/start-worker.sh

RUN mkdir -p /opt/lab/classes /oracle /opt/spark/work \
    && javac -d /opt/lab/classes /tmp/WitnessMain.java \
    && jar --create --file /opt/lab/witness.jar -C /opt/lab/classes . \
    && chmod 0755 /opt/lab/start-master.sh /opt/lab/start-worker.sh \
    && chown -R spark:spark /opt/lab /oracle /opt/spark/conf /opt/spark/work \
    && rm -f /tmp/WitnessMain.java

USER spark
WORKDIR /opt/spark
