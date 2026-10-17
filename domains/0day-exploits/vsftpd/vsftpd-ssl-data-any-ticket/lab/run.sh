#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-vsftpd-ssl-data-any-ticket}"
export PYTHONUNBUFFERED=1

LABEL="vsftpd-ssl-data-any-ticket"
WITNESS="VSFTPD-SSL-DATA-ANY-TICKET-WITNESS"
TAR="vsftpd-3.0.5.tar.gz"
TAR_SHA256="26b602ae454b0ba6d99ef44a09b6b9e0dfa7f67228106736df1f278c70bc91d3"
TAR_URL="https://security.appspot.com/downloads/vsftpd-3.0.5.tar.gz"

down() {
  echo "== docker compose down -v =="
  docker compose -p "${COMPOSE_PROJECT_NAME}" down -v --remove-orphans || true
}

fail_setup() {
  local reason="$1"
  echo "FAIL ${LABEL} reason=${reason} ${WITNESS}" | tee poc-last-run.txt
  exit 1
}

verify_tarball() {
  python3 - "${TAR}" "${TAR_SHA256}" <<'PY'
import hashlib
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
want = sys.argv[2]
got = hashlib.sha256(path.read_bytes()).hexdigest()
if got != want:
    raise SystemExit(f"sha256-mismatch got={got} want={want}")
print(f"tarball-ok sha256={got}")
PY
}

trap down EXIT

echo "== docker compose down (clean) =="
down

if [[ ! -f "${TAR}" ]]; then
  echo "== stage ${TAR} =="
  if ! wget -q -O "${TAR}" "${TAR_URL}"; then
    rm -f "${TAR}"
    if [[ -f /tmp/vsftpd-3.0.5.tar.gz ]]; then
      cp /tmp/vsftpd-3.0.5.tar.gz "${TAR}"
    else
      fail_setup "tarball-missing"
    fi
  fi
fi
verify_tarball

echo "== docker compose up --build =="
up_ok=0
for attempt in $(seq 1 5); do
  if docker compose -p "${COMPOSE_PROJECT_NAME}" up --build -d; then
    up_ok=1
    break
  fi
  echo "compose-up-retry attempt=${attempt}"
  sleep 8
  down
done
if [[ "${up_ok}" != 1 ]]; then
  echo "== compose logs (up failed) =="
  docker compose -p "${COMPOSE_PROJECT_NAME}" logs --no-color --tail=80 || true
  fail_setup "compose-up-failed"
fi

echo "== wait for FTP 220 on 127.0.0.1:18700 =="
ok=0
for i in $(seq 1 90); do
  if python3 - <<'PY'
import socket

sock = socket.create_connection(("127.0.0.1", 18700), 2)
try:
    banner = sock.recv(256)
finally:
    sock.close()
if not banner.startswith(b"220"):
    raise SystemExit(1)
PY
  then
    ok=1
    echo "ftp-ready attempt=${i}"
    break
  fi
  echo "ftp-wait attempt=${i}"
  sleep 2
done
if [[ "${ok}" != 1 ]]; then
  echo "== compose logs (not ready) =="
  docker compose -p "${COMPOSE_PROJECT_NAME}" logs --no-color --tail=120 || true
  fail_setup "ftp-not-ready"
fi

echo "== poc.py =="
set +e
python3 ./poc.py | tee poc-last-run.txt
rc=${PIPESTATUS[0]}
set -e

if ! tail -n1 poc-last-run.txt 2>/dev/null | grep -qE '^(SUCCESS|FAIL) '; then
  echo "FAIL ${LABEL} reason=poc-exit=${rc} ${WITNESS}" >> poc-last-run.txt
  rc=1
fi

exit "${rc}"
