FROM eclipse-temurin:21-jdk-jammy

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    WITNESS=SPARK-RPC-STREAM-UNAUTH-WITNESS

WORKDIR /lab

RUN useradd --uid 65532 --user-group --create-home \
        --home-dir /home/lab --shell /usr/sbin/nologin lab \
    && mkdir -p /opt/repl-classes /oracle \
    && printf 'IN-DIR-OK\n' > /opt/repl-classes/hello.txt \
    && printf '%s\n' "${WITNESS}" > /oracle/secret \
    && chmod 0755 /opt/repl-classes /oracle \
    && chmod 0644 /opt/repl-classes/hello.txt /oracle/secret \
    && chown -R lab:lab /opt/repl-classes /lab

COPY gadget/Gadget.java /lab/Gadget.java

RUN javac /lab/Gadget.java \
    && chmod 0644 /lab/Gadget.java /lab/*.class \
    && chown lab:lab /lab/Gadget.java /lab/*.class

USER lab
EXPOSE 18910
CMD ["java", "-cp", "/lab", "Gadget"]
