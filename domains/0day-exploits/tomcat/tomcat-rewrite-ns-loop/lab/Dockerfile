FROM eclipse-temurin:17-jre-jammy

ENV CATALINA_HOME=/usr/local/tomcat \
    PATH=/usr/local/tomcat/bin:/opt/java/openjdk/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

WORKDIR /usr/local/tomcat

# Official library/tomcat:11.0.27-jre17 is not published; pin the 11.0.27 binary dist.
ARG TOMCAT_VERSION=11.0.27
ARG TOMCAT_SHA512=a617896307cada4884b24f80c4e977ddad8b3e0f88ce0e2a6eea29d5f332498e276ae5976c227a9c8daecf05c7c90def684a3766dd5a81f47a56d8b1adf43dc3

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && curl -fsSL -o /tmp/tomcat.tar.gz \
        "https://archive.apache.org/dist/tomcat/tomcat-11/v${TOMCAT_VERSION}/bin/apache-tomcat-${TOMCAT_VERSION}.tar.gz" \
    && echo "${TOMCAT_SHA512}  /tmp/tomcat.tar.gz" | sha512sum -c - \
    && tar -xzf /tmp/tomcat.tar.gz --strip-components=1 \
    && rm /tmp/tomcat.tar.gz \
    && grep -q "Apache Tomcat Version ${TOMCAT_VERSION}" RELEASE-NOTES \
    && mkdir -p conf/Catalina/localhost \
    && rm -rf webapps/docs webapps/examples webapps/host-manager \
    && apt-get purge -y curl \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*

COPY conf/server.xml /usr/local/tomcat/conf/server.xml
COPY conf/rewrite.config /usr/local/tomcat/conf/Catalina/localhost/rewrite.config

EXPOSE 8080
CMD ["catalina.sh", "run"]
