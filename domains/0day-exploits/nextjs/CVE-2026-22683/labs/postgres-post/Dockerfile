FROM postgres:16

# Install curl for payload delivery
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*

COPY init.sql /docker-entrypoint-initdb.d/
