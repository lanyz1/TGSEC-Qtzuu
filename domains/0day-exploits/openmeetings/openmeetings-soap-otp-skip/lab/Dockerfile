FROM --platform=linux/amd64 eclipse-temurin:21-jre AS jre
FROM --platform=linux/amd64 apache/openmeetings:min-9.1.0
# Published min-9.1.0 has Tomcat/OM but no JRE. Copy a stock Java 21 runtime.
COPY --from=jre /opt/java/openjdk /opt/java/openjdk
ENV JAVA_HOME=/opt/java/openjdk
ENV JRE_HOME=/opt/java/openjdk
ENV PATH="/opt/java/openjdk/bin:${PATH}"
