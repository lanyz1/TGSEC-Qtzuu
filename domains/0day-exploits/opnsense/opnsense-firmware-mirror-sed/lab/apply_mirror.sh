#!/bin/sh
# Out-of-pin opnsense-update mod_mirrorurl. GNU sed: no Darwin -i ''.
# Pin form:
#   sed -i '' '/'"${URL_KEY}"'/s|".*${ABI}|"'"${DO_MIRRORURL#"-m "}"'/${ABI}|' ${ORIGIN}
set -eu

ORIGIN="${1:?}"
DO_MIRRORURL="${2:?}"
URL_KEY="^[[:space:]]*url:[[:space:]]*"

sed -i '/'"${URL_KEY}"'/s|".*${ABI}|"'"${DO_MIRRORURL#"-m "}"'/${ABI}|' "${ORIGIN}"
