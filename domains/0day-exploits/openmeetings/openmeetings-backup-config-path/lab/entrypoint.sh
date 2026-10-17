#!/bin/bash
set -euo pipefail

work="${work:-/opt}"
OM_HOME="${OM_HOME:-/opt/openmeetings}"
OM_DATA_DIR="${OM_DATA_DIR:-/opt/omdata}"
OM_DB_HOST="${OM_DB_HOST:-db}"
OM_DB_PORT="${OM_DB_PORT:-3306}"
OM_DB_NAME="${OM_DB_NAME:-openmeetings}"
OM_DB_USER="${OM_DB_USER:-om_admin}"
OM_DB_PASS="${OM_DB_PASS:-12345}"
OM_DB_TYPE="${OM_DB_TYPE:-mysql}"
OM_USER="${OM_USER:-om_admin}"
OM_PASS="${OM_PASS:-1Q2w3e4r5t^y}"
OM_KURENTO_WS_URL="${OM_KURENTO_WS_URL:-ws://127.0.0.1:9/kurento}"
SERVER_TZ="${SERVER_TZ:-UTC}"
DAEMON_USER="${DAEMON_USER:-nobody}"
export JAVA_HOME="${JAVA_HOME:-/opt/java/openjdk}"
export PATH="${JAVA_HOME}/bin:${PATH}"
MARKER="${OM_DATA_DIR}/.lab-installed"

echo "lab-entrypoint: java=$(command -v java || true) JAVA_HOME=${JAVA_HOME}"
echo "lab-entrypoint: wait for ${OM_DB_HOST}:${OM_DB_PORT}"
ready=0
for i in $(seq 1 90); do
  if (echo >/dev/tcp/"${OM_DB_HOST}"/"${OM_DB_PORT}") >/dev/null 2>&1; then
    ready=1
    echo "lab-entrypoint: db tcp-up attempt=${i}"
    break
  fi
  echo "lab-entrypoint: db-wait attempt=${i}"
  sleep 2
done
if [[ "${ready}" != 1 ]]; then
  echo "lab-entrypoint: db never became reachable"
  exit 1
fi

if [[ -f "${work}/om_euser.sh" ]]; then
  # shellcheck disable=SC1091
  . "${work}/om_euser.sh"
fi

mkdir -p "${OM_DATA_DIR}" "${OM_HOME}/logs"
CLASSES_HOME="${OM_HOME}/webapps/openmeetings/WEB-INF/classes"
DB_CFG_HOME="${CLASSES_HOME}/META-INF"
cp "${DB_CFG_HOME}/${OM_DB_TYPE}_persistence.xml" "${DB_CFG_HOME}/persistence.xml"
sed -i "s|localhost:3306/openmeetings?|${OM_DB_HOST}:${OM_DB_PORT}/${OM_DB_NAME}?serverTimezone=${SERVER_TZ}\\&amp;allowPublicKeyRetrieval=true\\&amp;|g" "${DB_CFG_HOME}/persistence.xml"
sed -i "s/Username=/Username=${OM_DB_USER}/g; s/Password=/Password=${OM_DB_PASS}/g" "${DB_CFG_HOME}/persistence.xml"
sed -i "s|useSSL=false|useSSL=false\\&amp;allowPublicKeyRetrieval=true|g" "${DB_CFG_HOME}/persistence.xml" || true
sed -i "s|ws://127.0.0.1:8888/kurento|${OM_KURENTO_WS_URL}|g" "${CLASSES_HOME}/openmeetings.properties"

export JAVA_OPTS="-Xms256m -Xmx1024m -Djava.awt.headless=true -Djava.security.egd=file:/dev/./urandom -Dopenjpa.serialization.class.blacklist=* -Dopenjpa.serialization.class.whitelist=[B,java.util,org.apache.openjpa,org.apache.openmeetings.db.entity"
export CATALINA_OPTS="-DDATA_DIR=${OM_DATA_DIR}"

chown -R "${DAEMON_USER}" "${OM_HOME}" "${OM_DATA_DIR}" || true

if [[ ! -f "${MARKER}" ]]; then
  echo "lab-entrypoint: admin.sh install"
  cd "${OM_HOME}"
  ./admin.sh -v -i -tz UTC -email labadmin@lab.invalid -group lab \
    -user "${OM_USER}" --password "${OM_PASS}" \
    --db-type mysql --db-host "${OM_DB_HOST}" --db-port "${OM_DB_PORT}" \
    --db-name "${OM_DB_NAME}" --db-user "${OM_DB_USER}" --db-pass "${OM_DB_PASS}" \
    --system-email-address noreply@lab.invalid --smtp-server 127.0.0.1 --smtp-port 9
  touch "${MARKER}"
  echo "lab-entrypoint: install complete"
else
  echo "lab-entrypoint: install marker present, skip admin.sh"
fi

chown -R "${DAEMON_USER}" "${OM_HOME}" "${OM_DATA_DIR}" || true
echo "lab-entrypoint: catalina"
cd "${OM_HOME}"
exec sudo --preserve-env=JAVA_HOME --preserve-env=PATH --preserve-env=JAVA_OPTS --preserve-env=CATALINA_OPTS \
  -u "${DAEMON_USER}" HOME=/tmp "${OM_HOME}/bin/catalina.sh" run
