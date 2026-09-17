#!/bin/bash
# Redis 8.8.0 official amd64 image pinned to the exploit's offsets.
exec docker run --rm --name redis-server-poc \
  -p 127.0.0.1:6379:6379 \
  redis@sha256:234c902a2db49461a129e2d4aeff85b28cf20187ed274a67f6e50995fa713c7b \
  redis-server --protected-mode no --save '' --appendonly no
