FROM --platform=linux/amd64 eclipse-temurin:21-jre-noble AS jre

FROM --platform=linux/amd64 apache/openmeetings:min-9.1.0
USER root
COPY --from=jre /opt/java/openjdk /opt/java/openjdk
ENV JAVA_HOME=/opt/java/openjdk
ENV PATH="/opt/java/openjdk/bin:${PATH}"
RUN ln -sf /opt/java/openjdk/bin/java /usr/bin/java
