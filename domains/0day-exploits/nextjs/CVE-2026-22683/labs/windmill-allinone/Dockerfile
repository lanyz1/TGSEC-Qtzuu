# Windmill All-in-One (PostgreSQL + Windmill in same container)
# For testing path traversal -> PostgreSQL file dumps
# Based on vulnerable version 1.394.4

FROM ghcr.io/windmill-labs/windmill:1.394.4

USER root

# Install PostgreSQL
RUN apt-get update && apt-get install -y \
    postgresql-15 \
    postgresql-contrib-15 \
    supervisor \
    && rm -rf /var/lib/apt/lists/*

# Setup PostgreSQL data directory
RUN mkdir -p /var/lib/postgresql/data && \
    chown -R postgres:postgres /var/lib/postgresql && \
    chmod 700 /var/lib/postgresql/data

# Initialize PostgreSQL
USER postgres
RUN /usr/lib/postgresql/15/bin/initdb -D /var/lib/postgresql/data

# Create windmill database
RUN /usr/lib/postgresql/15/bin/pg_ctl -D /var/lib/postgresql/data -l /tmp/pg.log start && \
    sleep 2 && \
    createdb windmill && \
    psql -c "ALTER USER postgres PASSWORD 'changeme';" && \
    /usr/lib/postgresql/15/bin/pg_ctl -D /var/lib/postgresql/data stop

USER root

# Copy config and init scripts
COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf
COPY init-testdata.sql /init-testdata.sql
COPY init-testdata.sh /init-testdata.sh
RUN chmod +x /init-testdata.sh

EXPOSE 8000

CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/conf.d/supervisord.conf"]
