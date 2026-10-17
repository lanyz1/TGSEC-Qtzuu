#!/bin/bash
# Lab wrapper: patch JDBC, wait for MySQL, CLI-install once, then catalina.
set -euo pipefail

. "${work}/om_euser.sh"
echo "OM server of type ${OM_TYPE} will be run"
CLASSES_HOME="${OM_HOME}/webapps/openmeetings/WEB-INF/classes"
export JAVA_HOME="${JAVA_HOME:-/opt/java/openjdk}"
export JRE_HOME="${JRE_HOME:-${JAVA_HOME}}"
export PATH="${JAVA_HOME}/bin:${PATH}"
export JAVA_OPTS="-Djava.awt.headless=true -Djava.security.egd=file:/dev/./urandom -Dopenjpa.serialization.class.blacklist=* -Dopenjpa.serialization.class.whitelist=[B,java.util,org.apache.openjpa,org.apache.openmeetings.db.entity"

echo "IOC java $($JAVA_HOME/bin/java -version 2>&1 | head -n1)"

DB_CFG_HOME="${CLASSES_HOME}/META-INF"
cp "${DB_CFG_HOME}/${OM_DB_TYPE}_persistence.xml" "${DB_CFG_HOME}/persistence.xml"
case ${OM_DB_TYPE} in
  mysql)
    sed -i "s|localhost:3306/openmeetings?|${OM_DB_HOST}:${OM_DB_PORT}/${OM_DB_NAME}?serverTimezone=${SERVER_TZ}\&amp;|g" "${DB_CFG_HOME}/persistence.xml"
    sed -i "s|useSSL=false\&amp;|useSSL=false\&amp;allowPublicKeyRetrieval=true\&amp;|g" "${DB_CFG_HOME}/persistence.xml"
    ;;
  postgresql)
    sed -i "s|localhost:5432/openmeetings|${OM_DB_HOST}:${OM_DB_PORT}/${OM_DB_NAME}|g" "${DB_CFG_HOME}/persistence.xml"
    ;;
esac
sed -i "s/Username=/Username=${OM_DB_USER}/g; s/Password=/Password=${OM_DB_PASS}/g" "${DB_CFG_HOME}/persistence.xml"

if [ ! -d "${OM_DATA_DIR}" ]; then
  echo "Make data dir ${OM_DATA_DIR}"
  mkdir -p "${OM_DATA_DIR}"
fi
chown -R "${DAEMON_USER}" "${OM_DATA_DIR}" || true
sed -i "s|ws://127.0.0.1:8888/kurento|${OM_KURENTO_WS_URL}|g" "${CLASSES_HOME}/openmeetings.properties"
export CATALINA_OPTS="-DDATA_DIR=${OM_DATA_DIR}"

echo "IOC wait-db ${OM_DB_HOST}:${OM_DB_PORT}"
db_ok=0
for i in $(seq 1 90); do
  if (echo >/dev/tcp/${OM_DB_HOST}/${OM_DB_PORT}) >/dev/null 2>&1; then
    echo "IOC db-tcp-ready attempt=${i}"
    db_ok=1
    break
  fi
  echo "IOC db-wait attempt=${i}"
  sleep 2
done
if [ "${db_ok}" != 1 ]; then
  echo "FAIL db not reachable"
  exit 1
fi
sleep 3

MARKER="${OM_DATA_DIR}/.om-installed"
if [ ! -f "${MARKER}" ]; then
  echo "IOC admin-install start"
  cd "${OM_HOME}"
  sudo --preserve-env=JAVA_HOME --preserve-env=JRE_HOME --preserve-env=PATH --preserve-env=JAVA_OPTS --preserve-env=CATALINA_OPTS --preserve-env=JDK_JAVA_OPTIONS \
    -u "${DAEMON_USER}" HOME=/tmp \
    ./admin.sh -v -i --force \
      -tz Europe/Berlin \
      -email om-admin@example.com \
      -group labgroup \
      -user "${OM_USER}" \
      --password "${OM_PASS}"
  touch "${MARKER}"
  chown "${DAEMON_USER}" "${MARKER}" || true
  echo "IOC admin-install done"
else
  echo "IOC admin-install skipped marker present"
fi

# Load otp.enabled before catalina so Application.init sees it (no compose restart).
OTP_SECRET="JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
echo "IOC enable-otp-before-catalina"
python3 /opt/mysql_lab.py \
  "${OM_DB_HOST}" "${OM_DB_PORT}" "${OM_DB_USER}" "${OM_DB_PASS}" "${OM_DB_NAME}" \
  "UPDATE configuration SET value='true' WHERE om_key='otp.enabled'" \
  "UPDATE om_user SET otp_secret='${OTP_SECRET}', otp_recovery='lab-recovery-aaaa lab-recovery-bbbb' WHERE login='${OM_USER}'"
echo "IOC otp-sql-done"

echo "Current max open files is $(su nobody --shell /bin/bash --command 'ulimit -n')"
cd "${OM_HOME}"
exec sudo --preserve-env=JAVA_HOME --preserve-env=JRE_HOME --preserve-env=PATH --preserve-env=JAVA_OPTS --preserve-env=CATALINA_OPTS --preserve-env=JDK_JAVA_OPTIONS \
  -u "${DAEMON_USER}" HOME=/tmp \
  "${OM_HOME}/bin/catalina.sh" run
