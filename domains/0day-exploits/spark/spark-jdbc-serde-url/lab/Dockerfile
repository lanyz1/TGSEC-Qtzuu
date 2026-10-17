FROM eclipse-temurin:21-jdk-jammy

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends libpostgresql-jdbc-java \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /gadget

COPY gadget/SerdeJdbcGadget.java /gadget/SerdeJdbcGadget.java

RUN test -r /usr/share/java/postgresql.jar \
    && javac -cp /usr/share/java/postgresql.jar SerdeJdbcGadget.java

CMD ["sleep", "infinity"]
