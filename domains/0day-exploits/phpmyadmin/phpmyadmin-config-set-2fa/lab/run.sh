#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-phpmyadmin-config-set-2fa}"
export PYTHONUNBUFFERED=1
export PMA_URL="${PMA_URL:-http://127.0.0.1:19280}"

LABEL="phpmyadmin-config-set-2fa"
WITNESS="PMA-CONFIG-SET-2FA-WITNESS"
PIN_TAG="RELEASE_5_2_3"
PIN_SHA="962857e4f63d42e38f11ff4d63f5e722018add76"
SRC_DEST="src"

down() {
  echo "== docker compose down -v =="
  docker compose -p "${COMPOSE_PROJECT_NAME}" down -v --remove-orphans || true
}

trap down EXIT

fail_setup() {
  local reason="$1"
  echo "FAIL ${LABEL} ${reason} ${WITNESS}" | tee poc-last-run.txt
  exit 1
}

copy_from_review() {
  local cand
  for cand in \
    "../../vendors/phpmyadmin/src" \
    "../../client-reviews/phpmyadmin/src" \
    "../client-reviews/phpmyadmin/src"; do
    if [[ -d "${cand}/.git" && -f "${cand}/libraries/classes/Controllers/Config/SetConfigController.php" ]]; then
      local got
      got="$(git -C "${cand}" rev-parse HEAD)"
      echo "review-tree path=${cand} sha=${got} expect=${PIN_SHA}"
      if [[ "${got}" == "${PIN_SHA}" ]]; then
        rm -rf "${SRC_DEST}"
        mkdir -p "${SRC_DEST}"
        tar -C "${cand}" --exclude .git --exclude test --exclude po --exclude doc -cf - . \
          | tar -C "${SRC_DEST}" -xf -
        echo "checkout-ok tag=${PIN_TAG} sha=${got} source=review-copy"
        return 0
      fi
    fi
  done
  return 1
}

clone_pin() {
  if [[ -d "${SRC_DEST}/.git" ]]; then
    local got
    got="$(git -C "${SRC_DEST}" rev-parse HEAD)"
    if [[ "${got}" == "${PIN_SHA}" ]]; then
      echo "checkout-ok tag=${PIN_TAG} sha=${got} source=existing-clone"
      return 0
    fi
    echo "reclone tag=${PIN_TAG} got=${got} expect=${PIN_SHA}"
    rm -rf "${SRC_DEST}"
  fi
  GIT_TERMINAL_PROMPT=0 git clone --depth 1 --branch "${PIN_TAG}" \
    https://github.com/phpmyadmin/phpmyadmin.git "${SRC_DEST}"
  local got
  got="$(git -C "${SRC_DEST}" rev-parse HEAD)"
  echo "checkout tag=${PIN_TAG} sha=${got} expect=${PIN_SHA}"
  if [[ "${got}" != "${PIN_SHA}" ]]; then
    GIT_TERMINAL_PROMPT=0 git -C "${SRC_DEST}" fetch --depth 1 origin "${PIN_SHA}"
    git -C "${SRC_DEST}" checkout -f "${PIN_SHA}"
    got="$(git -C "${SRC_DEST}" rev-parse HEAD)"
    echo "checkout-forced tag=${PIN_TAG} sha=${got}"
  fi
  if [[ "${got}" != "${PIN_SHA}" ]]; then
    fail_setup "unexpected-commit tag=${PIN_TAG} got=${got} expect=${PIN_SHA}"
  fi
  echo "checkout-ok tag=${PIN_TAG} sha=${got} source=git-clone"
}

echo "== pin ${PIN_TAG} ${PIN_SHA} =="
if ! copy_from_review; then
  clone_pin
fi
if [[ ! -f "${SRC_DEST}/libraries/classes/Controllers/Config/SetConfigController.php" ]]; then
  fail_setup "missing-set-config-controller"
fi

chmod +x poc.py

echo "== docker compose down (clean) =="
trap - EXIT
down
trap down EXIT

echo "== docker compose up --build =="
up_ok=0
for attempt in $(seq 1 5); do
  if docker compose -p "${COMPOSE_PROJECT_NAME}" up --build -d; then
    up_ok=1
    break
  fi
  echo "IOC compose-up-retry attempt=${attempt}"
  sleep 8
  down
done
if [[ "${up_ok}" != 1 ]]; then
  fail_setup "compose-up-failed"
fi

echo "== wait ${PMA_URL} =="
ready=0
for i in $(seq 1 90); do
  code="$(curl -sS -o /tmp/pma-config-set-2fa-ready.txt -w '%{http_code}' --max-time 8 \
    "${PMA_URL}/index.php?route=/" || true)"
  if [[ "${code}" == "200" ]]; then
    ready=1
    echo "IOC pma-ready attempt=${i} http=${code}"
    break
  fi
  echo "IOC pma-wait attempt=${i} http=${code}"
  sleep 2
done
if [[ "${ready}" != 1 ]]; then
  docker compose -p "${COMPOSE_PROJECT_NAME}" logs --no-color --tail=80 || true
  fail_setup "pma-not-ready"
fi

echo "== poc.py =="
set +e
python3 ./poc.py | tee poc-last-run.txt
rc=${PIPESTATUS[0]}
set -e

if ! tail -n1 poc-last-run.txt 2>/dev/null | grep -qE '^(SUCCESS|FAIL) '; then
  echo "FAIL ${LABEL} poc-exit=${rc} ${WITNESS}" >> poc-last-run.txt
  rc=1
fi

exit "${rc}"
