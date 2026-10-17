#!/bin/bash
set -euo pipefail

. "${work}/om_euser.sh"

echo "OM lab entrypoint type=${OM_TYPE} db=${OM_DB_HOST}:${OM_DB_PORT}/${OM_DB_NAME}"

export JAVA_HOME="${JAVA_HOME:-/usr/lib/jvm/java-21-openjdk-amd64}"
if [ ! -x "${JAVA_HOME}/bin/java" ]; then
  JAVA_BIN="$(command -v java)"
  JAVA_HOME="$(dirname "$(dirname "$(readlink -f "${JAVA_BIN}")")")"
  export JAVA_HOME
fi
export JRE_HOME="${JRE_HOME:-${JAVA_HOME}}"
export PATH="${JAVA_HOME}/bin:${PATH}"

export JAVA_OPTS="-Xms256m -Xmx1024m -Djava.awt.headless=true -Djava.security.egd=file:/dev/./urandom -Dopenjpa.serialization.class.blacklist=* -Dopenjpa.serialization.class.whitelist=[B,java.util,org.apache.openjpa,org.apache.openmeetings.db.entity"
export CATALINA_OPTS="-DDATA_DIR=${OM_DATA_DIR}"

CLASSES_HOME="${OM_HOME}/webapps/openmeetings/WEB-INF/classes"
DB_CFG_HOME="${CLASSES_HOME}/META-INF"
cp "${DB_CFG_HOME}/${OM_DB_TYPE}_persistence.xml" "${DB_CFG_HOME}/persistence.xml"
sed -i "s|localhost:3306/openmeetings?|${OM_DB_HOST}:${OM_DB_PORT}/${OM_DB_NAME}?serverTimezone=${SERVER_TZ}\&amp;|g" "${DB_CFG_HOME}/persistence.xml"
sed -i -E "s/Username=[^,]*/Username=${OM_DB_USER}/; s/Password=[^,^\"]*/Password=${OM_DB_PASS}/" "${DB_CFG_HOME}/persistence.xml"
sed -i "s|useSSL=false\&amp;|useSSL=false\&amp;allowPublicKeyRetrieval=true\&amp;|g" "${DB_CFG_HOME}/persistence.xml"
if [ ! -d "${OM_DATA_DIR}" ]; then
  mkdir -p "${OM_DATA_DIR}"
fi
sed -i "s|ws://127.0.0.1:8888/kurento|${OM_KURENTO_WS_URL}|g" "${CLASSES_HOME}/openmeetings.properties"
chown -R "${DAEMON_USER}" "${OM_HOME}" "${OM_DATA_DIR}"

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
sleep 5

MARKER="${OM_DATA_DIR}/.lab-installed"
if [ ! -f "${MARKER}" ]; then
  echo "installing OpenMeetings schema"
  cd "${OM_HOME}"
  sudo --preserve-env=JAVA_OPTS --preserve-env=JAVA_HOME --preserve-env=JRE_HOME --preserve-env=PATH \
    -u "${DAEMON_USER}" HOME=/tmp ./admin.sh -v -i -tz UTC \
    -email admin@example.com -group group \
    -user "${OM_USER}" --password "${OM_PASS}" \
    --db-type mysql --db-host "${OM_DB_HOST}" --db-port "${OM_DB_PORT}" \
    --db-name "${OM_DB_NAME}" --db-user "${OM_DB_USER}" --db-pass "${OM_DB_PASS}"
  touch "${MARKER}"
  chown "${DAEMON_USER}" "${MARKER}"
  echo "install complete"
fi

echo "starting catalina"
cd "${OM_HOME}"
exec sudo --preserve-env=JAVA_OPTS --preserve-env=CATALINA_OPTS --preserve-env=JAVA_HOME --preserve-env=JRE_HOME --preserve-env=PATH \
  -u "${DAEMON_USER}" HOME=/tmp "${OM_HOME}/bin/catalina.sh" run
