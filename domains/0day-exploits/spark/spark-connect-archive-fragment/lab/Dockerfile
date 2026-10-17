FROM eclipse-temurin:21-jdk-jammy

ENV DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8

RUN useradd --uid 1000 --create-home --home-dir /lab spark

WORKDIR /lab

COPY Gadget.java /lab/Gadget.java

RUN javac /lab/Gadget.java \
    && mkdir -p /lab/root /lab/staging /lab/oracle \
    && chown -R spark:spark /lab

USER spark

EXPOSE 18930

CMD ["java", "-cp", "/lab", "Gadget"]
