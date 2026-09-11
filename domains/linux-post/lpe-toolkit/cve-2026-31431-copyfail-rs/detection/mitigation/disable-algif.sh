#!/usr/bin/env bash
# CopyFail (CVE-2026-31431) — apply 2-line modprobe mitigation
#
# Effective ONLY when CONFIG_CRYPTO_USER_API_AEAD=m (loadable module).
# If your kernel was built with =y (built-in), this script will warn and
# exit non-zero; rebuild kernel as =m, apply seccomp filter, or update to
# a kernel including mainline commit a664bf3d603d.

set -euo pipefail

CONFIG="/boot/config-$(uname -r)"
if [ -r "$CONFIG" ]; then
    state=$(grep -E '^CONFIG_CRYPTO_USER_API_AEAD=' "$CONFIG" | head -1 | cut -d= -f2 || true)
    case "$state" in
        y)
            echo "ERROR: CONFIG_CRYPTO_USER_API_AEAD=y in $CONFIG" >&2
            echo "Modprobe blacklist is INEFFECTIVE on this kernel." >&2
            echo "Options:" >&2
            echo "  1. Rebuild kernel with =m" >&2
            echo "  2. Apply seccomp filter that blocks socket(AF_ALG, ...)" >&2
            echo "  3. Update to kernel >= mainline commit a664bf3d603d" >&2
            exit 2
            ;;
        m)
            echo "OK: CONFIG_CRYPTO_USER_API_AEAD=m — mitigation will be effective"
            ;;
        "")
            echo "WARNING: CONFIG_CRYPTO_USER_API_AEAD not found in $CONFIG"
            echo "Proceeding anyway; verify after with: lsmod | grep algif_aead"
            ;;
        *)
            echo "WARNING: unexpected config value '$state' — proceeding"
            ;;
    esac
else
    echo "WARNING: $CONFIG not readable; cannot verify =m precondition"
fi

echo "install algif_aead /bin/false" | sudo tee /etc/modprobe.d/disable-algif.conf >/dev/null
sudo rmmod algif_aead 2>/dev/null || true
echo "Mitigation applied."
echo "Verify: modprobe algif_aead 2>&1 | grep -q '/bin/false' && echo BLOCKED"
