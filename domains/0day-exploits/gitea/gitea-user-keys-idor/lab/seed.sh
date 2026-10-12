#!/usr/bin/env bash
# Create victim + attacker and plant a witness SSH key on the victim.
set -euo pipefail
cd "$(dirname "$0")"

CID="${1:?container}"
WORKDIR="${2:-/tmp/gitea-key-idor}"
WITNESS="GHSA-GITEA-KEY-IDOR-WITNESS"
PASSWORD="LabPass123!"

mkdir -p "${WORKDIR}"

if [[ ! -f "${WORKDIR}/victim.pub" ]]; then
  ssh-keygen -t ed25519 -N "" -C "${WITNESS}" -f "${WORKDIR}/victim" >/dev/null
fi
if [[ ! -f "${WORKDIR}/attacker.pub" ]]; then
  ssh-keygen -t ed25519 -N "" -C "attacker-own-key" -f "${WORKDIR}/attacker" >/dev/null
fi

create_user() {
  local name="$1"
  docker exec -u git "${CID}" gitea admin user create \
    --username "${name}" \
    --password "${PASSWORD}" \
    --email "${name}@localhost.invalid" \
    --must-change-password=false \
    >/dev/null 2>&1 || true
}

create_user victim
create_user attacker

python3 ./seed.py "${WORKDIR}"
