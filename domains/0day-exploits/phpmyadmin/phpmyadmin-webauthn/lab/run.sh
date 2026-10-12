#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
export COMPOSE_PROJECT_NAME=pma-webauthn-lab
echo "== docker compose up =="
docker compose up -d --build
echo "== wait for http =="
for i in $(seq 1 60); do
  if curl -fsS -o /dev/null http://127.0.0.1:18080/index.php?route=/; then
    echo "IOC pma-up"
    break
  fi
  sleep 2
  if [[ "$i" -eq 60 ]]; then
    echo "FAIL phpMyAdmin did not become ready"
    docker compose logs --tail=80
    exit 1
  fi
done
echo "== poc.py =="
python3 poc.py http://127.0.0.1:18080
