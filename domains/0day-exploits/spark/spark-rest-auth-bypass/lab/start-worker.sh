#!/usr/bin/env bash
set -euo pipefail
export SPARK_HOME="${SPARK_HOME:-/opt/spark}"
export SPARK_CONF_DIR="${SPARK_CONF_DIR:-${SPARK_HOME}/conf}"

ready=0
for _ in $(seq 1 90); do
  if python3 -c 'import urllib.request; urllib.request.urlopen("http://master:6066/v1/submissions/readyz", timeout=2)' \
    2>/dev/null; then
    ready=1
    break
  fi
  sleep 2
done
if [[ "${ready}" != 1 ]]; then
  echo "master REST /v1/submissions/readyz not ready" >&2
  exit 1
fi

exec "${SPARK_HOME}/bin/spark-class" org.apache.spark.deploy.worker.Worker \
  "spark://${SPARK_MASTER_HOST:-master}:${SPARK_MASTER_PORT:-7077}" \
  --host "${SPARK_WORKER_HOST:-worker}" \
  --webui-port "${SPARK_WORKER_WEBUI_PORT:-8081}" \
  --work-dir "${SPARK_WORKER_DIR:-/opt/spark/work}" \
  --memory "${SPARK_WORKER_MEMORY:-1g}" \
  --cores "${SPARK_WORKER_CORES:-2}"
