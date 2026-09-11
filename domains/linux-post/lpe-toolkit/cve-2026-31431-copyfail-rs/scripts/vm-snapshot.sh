#!/usr/bin/env bash
# vm-snapshot.sh — capture a known-good baseline for cache-vs-disk diff testing.
# Run on the test VM BEFORE running the exploit. Stored hashes used by
# detection mode and post-exploit analysis to confirm what changed.

set -euo pipefail

OUT="${1:-./baseline.txt}"

CRITICAL=(
    /usr/bin/su
    /usr/bin/sudo
    /usr/bin/passwd
    /usr/bin/mount
    /usr/bin/umount
    /etc/passwd
    /etc/shadow
    /etc/sudoers
    /etc/pam.d/sudo
    /etc/pam.d/su
    /etc/pam.d/login
    /etc/pam.d/system-auth
    /etc/pam.d/common-auth
    /etc/nsswitch.conf
)

{
    echo "# CopyFail baseline — $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
    echo "# Host: $(hostname)"
    echo "# Kernel: $(uname -r)"
    echo
    for f in "${CRITICAL[@]}"; do
        if [ -r "$f" ]; then
            HASH=$(sha256sum "$f" 2>/dev/null | awk '{print $1}')
            SIZE=$(stat -c %s "$f")
            printf '%s  %d  %s\n' "$HASH" "$SIZE" "$f"
        else
            printf 'unreadable     -  %s\n' "$f"
        fi
    done
} | tee "$OUT"

echo
echo "Baseline written to $OUT"
echo "After exploit, re-run with a different output file and diff:"
echo "  diff <(sort baseline.txt) <(sort post-exploit.txt)"
