FROM eclipse-temurin:21-jdk-jammy

LABEL lab=spark-proxyuser-classpath

WORKDIR /opt/lab
COPY gadget/src /opt/lab/src

# Attacker jar is not on the gadget classpath; it only lands via constructed -cp.
RUN mkdir -p /tmp/evil-src/lab /tmp/evil-out \
    && cp /opt/lab/src/lab/WitnessMain.java /tmp/evil-src/lab/ \
    && javac -d /tmp/evil-out /tmp/evil-src/lab/WitnessMain.java \
    && jar --create --file /opt/lab/evil.jar -C /tmp/evil-out . \
    && cp /opt/lab/evil.jar /opt/lab/app.jar \
    && rm -rf /tmp/evil-src /tmp/evil-out

RUN mkdir -p /opt/lab/classes \
    && javac -d /opt/lab/classes \
        /opt/lab/src/lab/SparkLauncher.java \
        /opt/lab/src/lab/SparkSubmitCommandBuilder.java \
        /opt/lab/src/lab/SparkSubmit.java \
        /opt/lab/src/lab/LabMain.java \
        /opt/lab/src/lab/ReadyHttp.java

WORKDIR /work
EXPOSE 18950
CMD ["java", "-cp", "/opt/lab/classes", "lab.ReadyHttp"]
