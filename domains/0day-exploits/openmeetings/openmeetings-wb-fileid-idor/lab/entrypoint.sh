#!/bin/bash
set -euo pipefail

work="${work:-/opt}"
OM_HOME="${OM_HOME:-/opt/openmeetings}"
OM_DATA_DIR="${OM_DATA_DIR:-/opt/omdata}"
OM_DB_TYPE="${OM_DB_TYPE:-mysql}"
OM_DB_HOST="${OM_DB_HOST:-db}"
OM_DB_PORT="${OM_DB_PORT:-3306}"
OM_DB_NAME="${OM_DB_NAME:-openmeetings}"
OM_DB_USER="${OM_DB_USER:-om_admin}"
OM_DB_PASS="${OM_DB_PASS:-12345}"
OM_USER="${OM_USER:-om_admin}"
OM_PASS="${OM_PASS:-1Q2w3e4r5t^y}"
OM_KURENTO_WS_URL="${OM_KURENTO_WS_URL:-ws://127.0.0.1:8888/kurento}"
SERVER_TZ="${SERVER_TZ:-UTC}"
DAEMON_USER="${DAEMON_USER:-nobody}"

if [ -f "${work}/om_euser.sh" ]; then
  # shellcheck disable=SC1091
  . "${work}/om_euser.sh"
fi

export JAVA_HOME="${JAVA_HOME:-/usr/lib/jvm/java-21-openjdk-amd64}"
if [ ! -x "${JAVA_HOME}/bin/java" ]; then
  JAVA_BIN="$(command -v java || true)"
  if [ -n "${JAVA_BIN}" ]; then
    JAVA_HOME="$(dirname "$(dirname "$(readlink -f "${JAVA_BIN}")")")"
    export JAVA_HOME
  fi
fi
export JRE_HOME="${JRE_HOME:-${JAVA_HOME}}"
export PATH="${JAVA_HOME}/bin:${PATH}"

echo "OM lab entry type=${OM_TYPE:-min} java=${JAVA_HOME} db=${OM_DB_HOST}:${OM_DB_PORT}/${OM_DB_NAME}"

CLASSES_HOME="${OM_HOME}/webapps/openmeetings/WEB-INF/classes"
DB_CFG_HOME="${CLASSES_HOME}/META-INF"
cp "${DB_CFG_HOME}/${OM_DB_TYPE}_persistence.xml" "${DB_CFG_HOME}/persistence.xml"
sed -i "s|localhost:3306/openmeetings?|${OM_DB_HOST}:${OM_DB_PORT}/${OM_DB_NAME}?serverTimezone=${SERVER_TZ}\\&amp;allowPublicKeyRetrieval=true\\&amp;|g" "${DB_CFG_HOME}/persistence.xml"
sed -i -E "s/Username=[^,]*/Username=${OM_DB_USER}/; s/Password=[^,^\"]*/Password=${OM_DB_PASS}/" "${DB_CFG_HOME}/persistence.xml"
sed -i "s|useSSL=false\\&amp;|useSSL=false\\&amp;allowPublicKeyRetrieval=true\\&amp;|g" "${DB_CFG_HOME}/persistence.xml"
sed -i "s|ws://127.0.0.1:8888/kurento|${OM_KURENTO_WS_URL}|g" "${CLASSES_HOME}/openmeetings.properties"

mkdir -p "${OM_DATA_DIR}/upload/files" "${OM_DATA_DIR}/upload/stored" "${OM_HOME}/logs"
chown -R "${DAEMON_USER}" "${OM_HOME}" "${OM_DATA_DIR}" || true

export JAVA_OPTS="-Xms256m -Xmx1024m -Djava.awt.headless=true -Djava.security.egd=file:/dev/./urandom -DDATA_DIR=${OM_DATA_DIR} -Dopenjpa.serialization.class.blacklist=* -Dopenjpa.serialization.class.whitelist=[B,java.util,org.apache.openjpa,org.apache.openmeetings.db.entity"
export CATALINA_OPTS="-DDATA_DIR=${OM_DATA_DIR}"

echo "waiting for mysql ${OM_DB_HOST}:${OM_DB_PORT}"
ready=0
for _ in $(seq 1 90); do
  if (echo >/dev/tcp/"${OM_DB_HOST}"/"${OM_DB_PORT}") >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 2
done
if [ "${ready}" != 1 ]; then
  echo "mysql not reachable" >&2
  exit 1
fi
sleep 3

MARKER="${OM_DATA_DIR}/.lab-installed"
if [ ! -f "${MARKER}" ]; then
  echo "OM lab: admin.sh install"
  cd "${OM_HOME}"
  sudo --preserve-env=JAVA_OPTS --preserve-env=CATALINA_OPTS --preserve-env=JAVA_HOME --preserve-env=JRE_HOME --preserve-env=PATH \
    -u "${DAEMON_USER}" HOME=/tmp \
    ./admin.sh -v -i -tz UTC -email om_admin@example.com -group lab \
    -user "${OM_USER}" --password "${OM_PASS}" \
    --db-type mysql --db-host "${OM_DB_HOST}" --db-port "${OM_DB_PORT}" \
    --db-name "${OM_DB_NAME}" --db-user "${OM_DB_USER}" --db-pass "${OM_DB_PASS}" \
    --smtp-server 127.0.0.1 --smtp-port 9 \
    --system-email-address noreply@example.com
  touch "${MARKER}"
  chown "${DAEMON_USER}" "${MARKER}" || true
  echo "OM lab: install done"
fi

echo "OM lab: catalina"
cd "${OM_HOME}"
exec sudo --preserve-env=JAVA_OPTS --preserve-env=CATALINA_OPTS --preserve-env=JAVA_HOME --preserve-env=JRE_HOME --preserve-env=PATH \
  -u "${DAEMON_USER}" HOME=/tmp "${OM_HOME}/bin/catalina.sh" run
