#!/usr/bin/env bash

set -Eeuo pipefail

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
compose="$here/docker-compose.yml"
poc="$here/poc.pyz"
credentials="$here/.demo-credentials.json"
target="127.0.0.1:18935"
root_password="${DF_DEMO_ROOT_PASSWORD:-Password1!}"

for program in docker curl python3 git; do
    if ! command -v "$program" >/dev/null 2>&1; then
        printf '[error] missing required command: %s\n' "$program" >&2
        exit 1
    fi
done
docker compose version >/dev/null

printf '[1/4] Verifying the binary-free PoC and offline table\n'
(cd "$here" && python3 -S "$poc" self-test)

printf '\n[2/4] Recreating GitLab 18.11.3 from empty container state and volumes\n'
docker compose -f "$compose" down -v --remove-orphans
docker compose -f "$compose" up -d --force-recreate

started=$(date +%s)
last_report=-30
while ! curl -fsS "http://$target/users/sign_in" >/dev/null 2>&1; do
    now=$(date +%s)
    elapsed=$((now - started))
    if ((elapsed - last_report >= 30)); then
        printf '[fresh] GitLab is booting: %ss elapsed\n' "$elapsed"
        last_report=$elapsed
    fi
    if ((elapsed >= 900)); then
        printf '[error] GitLab did not become ready within 15 minutes\n' >&2
        exit 1
    fi
    sleep 5
done
printf '[ready] fresh GitLab web interface is serving requests\n'

printf '\n[3/4] Allowing normal Rails endpoints to settle\n'
sleep 15

printf '\n[4/4] Provisioning an ordinary user through public HTTP\n'
umask 077
temporary="$credentials.tmp.$$"
trap 'rm -f -- "$temporary"' EXIT
attempt=1
while ((attempt <= 12)); do
    if (cd "$here" && python3 -S "$poc" provision \
        --host "$target" \
        --root-password "$root_password" >"$temporary"); then
        break
    fi
    if ((attempt == 12)); then
        printf '[error] ordinary-user provisioning failed after %s attempts\n' "$attempt" >&2
        exit 1
    fi
    attempt=$((attempt + 1))
    sleep 5
done
python3 -c \
    'import json,sys; d=json.load(open(sys.argv[1])); assert d["admin"] is False and d["pat"].startswith("glpat-")' \
    "$temporary"
mv -f -- "$temporary" "$credentials"
chmod 600 "$credentials"
trap - EXIT

printf '[ready] fresh environment and ordinary-user credentials are prepared\n'
printf '[next] terminal 1: ./run_poc.sh listen 4555\n'
printf '[next] terminal 2: ./run_poc.sh exploit 4555\n'
