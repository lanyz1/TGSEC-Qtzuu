#!/usr/bin/env bash
set -euo pipefail
export SPARK_HOME="${SPARK_HOME:-/opt/spark}"
export SPARK_CONF_DIR="${SPARK_CONF_DIR:-${SPARK_HOME}/conf}"
exec "${SPARK_HOME}/bin/spark-class" org.apache.spark.deploy.master.Master \
  --host "${SPARK_MASTER_HOST:-master}" \
  --port "${SPARK_MASTER_PORT:-7077}" \
  --webui-port "${SPARK_MASTER_WEBUI_PORT:-8080}"
