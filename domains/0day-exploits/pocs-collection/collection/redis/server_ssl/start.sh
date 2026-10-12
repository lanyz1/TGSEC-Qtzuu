#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGE="${IMAGE:-redis@sha256:234c902a2db49461a129e2d4aeff85b28cf20187ed274a67f6e50995fa713c7b}"
NAME="${NAME:-redis-tls-uaf}"
REDIS_PORT="${PORT:-6380}"
STATE_DIR="$ROOT/.redis-target"
TLS_DIR="$STATE_DIR/tls"
CONF="$STATE_DIR/redis.conf"

command -v docker >/dev/null || { echo "error: docker not found" >&2; exit 1; }
command -v openssl >/dev/null || { echo "error: openssl not found" >&2; exit 1; }

mkdir -p "$TLS_DIR"
if [[ ! -f "$TLS_DIR/redis.crt" || ! -f "$TLS_DIR/redis.key" || ! -f "$TLS_DIR/ca.crt" ]]; then
  openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "$TLS_DIR/redis.key" \
    -out "$TLS_DIR/redis.crt" \
    -days 3650 \
    -subj "/CN=redis-tls-uaf" >/dev/null 2>&1
  cp "$TLS_DIR/redis.crt" "$TLS_DIR/ca.crt"
  chmod 0644 "$TLS_DIR"/*
fi

cat >"$CONF" <<CONF
port 0
tls-port 6379
tls-cert-file /tls/redis.crt
tls-key-file /tls/redis.key
tls-ca-cert-file /tls/ca.crt
tls-auth-clients no
protected-mode no
bind 0.0.0.0
save ""
appendonly no
dir /tmp
loglevel notice
user default on nopass ~* &* +ping +echo +eval +eval_ro +publish +hello +subscribe +lpos +rpush +del +hset
CONF

docker rm -f "$NAME" >/dev/null 2>&1 || true
cat <<EOF
container:  $NAME
image:      $IMAGE
host:       127.0.0.1:$REDIS_PORT
stop:       Ctrl-C

Redis logs and command output follow.
Run the exploit in another terminal after Redis is ready.
EOF

exec docker run --rm \
  --name "$NAME" \
  --pull missing \
  -p "127.0.0.1:${REDIS_PORT}:6379" \
  -v "$TLS_DIR:/tls:ro" \
  -v "$CONF:/usr/local/etc/redis/redis.conf:ro" \
  "$IMAGE" redis-server /usr/local/etc/redis/redis.conf
