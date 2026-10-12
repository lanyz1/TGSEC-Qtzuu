FROM maven:3.9.9-eclipse-temurin-21 AS build
WORKDIR /src
COPY gadget/pom.xml /src/pom.xml
COPY gadget/src /src/src
RUN mvn -B -DskipTests package

FROM eclipse-temurin:21-jre
LABEL lab=signal-server-dropwizard-admin
WORKDIR /app
COPY --from=build /src/target/lab-dropwizard-admin.jar /app/app.jar
COPY config/config.yml /app/config/config.yml
COPY config/patched.yml /app/config/patched.yml
EXPOSE 8080 8081
CMD ["java", "-jar", "/app/app.jar", "server", "/app/config/config.yml"]
