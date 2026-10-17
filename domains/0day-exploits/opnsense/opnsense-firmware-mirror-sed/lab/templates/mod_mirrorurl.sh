#!/bin/sh
# Out-of-pin opnsense/update src/update/opnsense-update.sh.in (mod_mirrorurl).
# Core pin 26.7.6 calls this via scripts/firmware/repos/OPNsense.php:
#   opnsense-update -sd -A <abi> -m <mirror>
# URL_KEY is set earlier in that script. Darwin/FreeBSD in-place is sed -i ''.
#
# URL_KEY="^[[:space:]]*url:[[:space:]]*"
# sed -i '' '/'"${URL_KEY}"'/s|".*${ABI}|"'"${DO_MIRRORURL#"-m "}"'/${ABI}|' ${ORIGIN}
#
# Lab GNU sed uses sed -i without Darwin -i ''. Same program text.

ORIGIN="${1:?}"
DO_MIRRORURL="${2:?}"
URL_KEY="^[[:space:]]*url:[[:space:]]*"
sed -i '/'"${URL_KEY}"'/s|".*${ABI}|"'"${DO_MIRRORURL#"-m "}"'/${ABI}|' "${ORIGIN}"
