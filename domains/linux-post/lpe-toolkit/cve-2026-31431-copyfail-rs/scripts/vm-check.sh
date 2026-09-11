#!/usr/bin/env bash
# vm-check.sh — pre-flight diagnostic for a target Linux host.
# Reports CopyFail (CVE-2026-31431) vulnerability status without firing exploit.
# Run on the target VM directly, or via SSH wrapper.

set -uo pipefail

bold() { printf '\033[1m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
red() { printf '\033[31m%s\033[0m\n' "$*"; }
yellow() { printf '\033[33m%s\033[0m\n' "$*"; }

bold "=== CopyFail VM check ==="
echo "Host: $(hostname) ($(hostname -I 2>/dev/null | awk '{print $1}'))"
echo "Time: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
echo

bold "--- Kernel ---"
KERNEL=$(uname -r)
echo "uname -r: $KERNEL"
echo "Build: $(uname -v)"
echo "Distro: $(lsb_release -d 2>/dev/null | cut -f2- || cat /etc/os-release | grep ^PRETTY_NAME= | cut -d'"' -f2)"
echo

# Kernel version >= 4.14 is required floor (AF_ALG iov_iter rework Aug 2017)
KMAJOR=$(echo "$KERNEL" | cut -d. -f1)
KMINOR=$(echo "$KERNEL" | cut -d. -f2)
if [ "$KMAJOR" -lt 4 ] || { [ "$KMAJOR" -eq 4 ] && [ "$KMINOR" -lt 14 ]; }; then
    red "  Kernel $KERNEL is BELOW vulnerable floor (4.14)"
    echo "  Status: NOT VULNERABLE (pre-2017)"
    exit 0
else
    green "  Kernel $KERNEL is in vulnerable range (>= 4.14)"
fi
echo

bold "--- AF_ALG family ---"
if lsmod | grep -q '^af_alg'; then
    green "  af_alg module: LOADED"
else
    yellow "  af_alg module: not loaded (may autoload)"
fi
if lsmod | grep -q '^algif_aead'; then
    green "  algif_aead module: LOADED"
    AEAD_LOADED=yes
else
    yellow "  algif_aead module: not loaded — will autoload on first AF_ALG aead bind"
    AEAD_LOADED=no
fi
echo

bold "--- algif_aead module availability ---"
AEAD_KO=$(find "/lib/modules/$KERNEL/" -name 'algif_aead.ko*' 2>/dev/null | head -1)
if [ -n "$AEAD_KO" ]; then
    green "  Module file present: $AEAD_KO"
else
    red "  algif_aead.ko NOT found in /lib/modules/$KERNEL/"
    echo "  Status: NOT EXPLOITABLE via algif_aead path"
    exit 0
fi
echo

bold "--- authencesn(hmac(sha256),cbc(aes)) template ---"
if [ "$AEAD_LOADED" = "no" ]; then
    yellow "  algif_aead not loaded; cannot enumerate templates without modprobe"
    yellow "  To check: sudo modprobe algif_aead && grep -i authencesn /proc/crypto"
else
    if grep -qi 'authencesn' /proc/crypto 2>/dev/null; then
        green "  authencesn template: AVAILABLE"
        grep -i authencesn /proc/crypto | head -10 | sed 's/^/    /'
    else
        yellow "  authencesn template not currently registered (may be on-demand)"
    fi
fi
echo

bold "--- Kernel patch status (heuristic) ---"
# Mainline fix: a664bf3d603d, April 2026.
# Distro backports started rolling around 2026-04-29.
BUILD_DATE=$(uname -v | grep -oE '[A-Z][a-z]{2} [A-Z][a-z]{2}\s+[0-9]+ [0-9:]+ UTC [0-9]+' | head -1)
echo "  Build date: $BUILD_DATE"
echo "  Mainline fix: April 2026 (commit a664bf3d603d)"
echo "  Distro backports: started ~2026-04-29"
echo "  Heuristic: if build date is before 2026-04-29, kernel almost certainly unpatched"
echo

bold "--- Critical files (detection targets) ---"
for f in /usr/bin/su /etc/passwd /etc/pam.d/sudo /etc/pam.d/system-auth /etc/pam.d/common-auth /etc/sudoers /etc/ld.so.preload; do
    if [ -e "$f" ]; then
        STAT=$(stat -c '%A %U:%G %s' "$f" 2>/dev/null)
        echo "  $f — $STAT"
    else
        echo "  $f — absent"
    fi
done
echo

bold "--- Verdict ---"
if [ -n "$AEAD_KO" ]; then
    if [ "$KMAJOR" -ge 4 ] && [ "$KMINOR" -ge 14 ] || [ "$KMAJOR" -ge 5 ]; then
        red "  LIKELY VULNERABLE"
        echo "  Recommended next step: load module + verify template"
        echo "    sudo modprobe algif_aead"
        echo "    grep -i authencesn /proc/crypto"
        echo "  Then build copyfail-rs and run --check for definitive answer."
    fi
else
    green "  NOT EXPLOITABLE via algif_aead (module unavailable)"
fi
