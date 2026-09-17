#!/bin/bash
# Wait for Windmill to complete migrations then insert test data

echo "[init] Waiting for PostgreSQL..."
until pg_isready -h localhost -U postgres -q; do
    sleep 1
done

echo "[init] Waiting for Windmill migrations (password table)..."
until psql -U postgres -d windmill -c "SELECT 1 FROM password LIMIT 1" &>/dev/null; do
    sleep 2
done

echo "[init] Inserting test data..."
psql -U postgres -d windmill -f /init-testdata.sql

echo "[init] Test data ready!"
