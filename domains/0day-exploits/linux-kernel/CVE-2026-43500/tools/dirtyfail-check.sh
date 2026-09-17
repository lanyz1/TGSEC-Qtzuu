#!/bin/bash
#
# dirtyfail-check.sh — defensive precondition probe for sysadmins
#
# A standalone bash script that reports whether this Linux host is
# exposed to Copy Fail (CVE-2026-31431) or Dirty Frag (CVE-2026-43284,
# CVE-2026-43500) exploitation by an unprivileged user.
#
# Does NOT require building DIRTYFAIL. Read-only — does not modify
# the system. Safe to run on production. Does not require root, but
# some checks are more accurate when run as root (kernel module
# inspection, sysctl reads).
#
# Usage:
#     bash dirtyfail-check.sh
#     # or pipe directly:
#     curl -sSL https://raw.githubusercontent.com/KaraZajac/DIRTYFAIL/main/tools/dirtyfail-check.sh | bash
#
# Exit codes:
#     0 = host is mitigated (kernel patched OR LSM blocks unprivileged path)
#     1 = host is VULNERABLE to at least one exploit path
#     2 = check error (couldn't determine state)

set -u

# ANSI colors only when stdout is a tty
if [ -t 1 ]; then
    RED='\033[1;31m'; YEL='\033[1;33m'; GRN='\033[1;32m'; CYN='\033[1;36m'; OFF='\033[0m'
else
    RED=''; YEL=''; GRN=''; CYN=''; OFF=''
fi

bad()  { printf "${RED}[!]${OFF} %s\n" "$*"; }
warn() { printf "${YEL}[~]${OFF} %s\n" "$*"; }
ok()   { printf "${GRN}[+]${OFF} %s\n" "$*"; }
info() { printf "${CYN}[*]${OFF} %s\n" "$*"; }

# ============================================================
# 1. Kernel version
# ============================================================
KVER=$(uname -r)
KMAJ=$(echo "$KVER" | cut -d. -f1)
KMIN=$(echo "$KVER" | cut -d. -f2)
info "kernel: $KVER  ($(uname -m))"

# Affected kernel window per the CVEs:
#   xfrm-ESP no-COW path: introduced 2017 (cac2661c53f3), fixed mainline
#                         f4c50a4034e6 (2026-05-07).
#   algif_aead/authencesn: introduced 2017 (72548b093ee3), fixed
#                          mainline a664bf3d.
#   rxkad page-cache write: introduced 2023-06 (2dc334f1a63a), no
#                            mainline patch yet at time of writing.
# Kernels 4.10 .. ~6.20 are within the broad window; older kernels
# may also be affected depending on backports.
if [ "$KMAJ" -lt 4 ] || { [ "$KMAJ" -eq 4 ] && [ "$KMIN" -lt 10 ]; }; then
    ok "kernel predates CVE introduction (cac2661c53f3, 2017-01)"
    NOT_IN_WINDOW=1
else
    info "kernel within affected window — checking other preconditions"
    NOT_IN_WINDOW=0
fi

# ============================================================
# 2. Module presence + blacklist
# ============================================================
MODS_VULNERABLE=0
MODS_BLACKLISTED=0
echo ""
info "module status:"
for m in algif_aead authencesn esp4 esp6 rxrpc; do
    if modinfo "$m" >/dev/null 2>&1; then
        if grep -rqE "^\s*install\s+$m\s+/bin/false" /etc/modprobe.d/ /lib/modprobe.d/ 2>/dev/null; then
            ok "  $m: blacklisted in modprobe.d (mitigated)"
            MODS_BLACKLISTED=$((MODS_BLACKLISTED + 1))
        elif lsmod | grep -q "^$m\b"; then
            warn "  $m: loaded — exposes the primitive"
            MODS_VULNERABLE=$((MODS_VULNERABLE + 1))
        else
            warn "  $m: present on disk, autoloads on use — exposes the primitive"
            MODS_VULNERABLE=$((MODS_VULNERABLE + 1))
        fi
    else
        ok "  $m: not on disk (kernel build doesn't ship it)"
    fi
done

# ============================================================
# 3. LSM / userns hardening
# ============================================================
echo ""
info "LSM / userns hardening:"

LSM_BLOCKS=0
if [ -r /proc/sys/kernel/apparmor_restrict_unprivileged_userns ]; then
    AA=$(cat /proc/sys/kernel/apparmor_restrict_unprivileged_userns 2>/dev/null)
    if [ "$AA" = "1" ]; then
        ok "  apparmor_restrict_unprivileged_userns=1 (Ubuntu-style hardening active)"
        # Confirm caps are actually blocked via empirical probe
        ( unshare -U bash -c 'echo deny > /proc/self/setgroups 2>/dev/null && exit 0 || exit 1' ) 2>/dev/null
        if [ $? -ne 0 ]; then
            ok "  empirical probe: unprivileged userns has no CAP_SYS_ADMIN — exploit infrastructure blocked"
            LSM_BLOCKS=1
        else
            warn "  empirical probe: caps survived unshare — sysctl set but enforcement may be off"
        fi
    else
        info "  apparmor_restrict_unprivileged_userns=$AA (not enforcing)"
    fi
else
    info "  no AppArmor userns sysctl (kernel without AA, or AA not loaded)"
fi

if command -v getenforce >/dev/null; then
    SE=$(getenforce 2>/dev/null)
    info "  SELinux: $SE"
fi

if [ -r /proc/sys/kernel/unprivileged_userns_clone ]; then
    UU=$(cat /proc/sys/kernel/unprivileged_userns_clone 2>/dev/null)
    if [ "$UU" = "0" ]; then
        ok "  unprivileged_userns_clone=0 (userns creation blocked entirely)"
        LSM_BLOCKS=1
    fi
fi

# ============================================================
# 4. PAM nullok (gates the rxrpc + backdoor → root step)
# ============================================================
echo ""
info "PAM configuration (gates rxrpc/backdoor → real root):"
PAM_NULLOK=0
if grep -rqE "pam_unix\.so\s+.*nullok" /etc/pam.d/ 2>/dev/null; then
    warn "  pam_unix nullok present — empty-password accounts can su to root"
    PAM_NULLOK=1
    grep -lE "pam_unix\.so\s+.*nullok" /etc/pam.d/ 2>/dev/null | sed 's/^/      /'
else
    ok "  pam_unix nullok NOT enabled — empty-password trick won't drop a root shell"
fi

# ============================================================
# 5. Verdict
# ============================================================
echo ""
echo "════════════════════════════════════════════════════════════"
echo "  VERDICT"
echo "════════════════════════════════════════════════════════════"

if [ "$NOT_IN_WINDOW" = "1" ]; then
    ok "kernel predates CVE introduction; no exposure"
    exit 0
elif [ "$LSM_BLOCKS" = "1" ]; then
    ok "LSM-mitigated: unprivileged userns operations are blocked"
    info "(kernel may still be vulnerable to root-level exploitation; ensure"
    info " your distro's kernel update with f4c50a4034e6 backport is applied"
    info " for full coverage.)"
    exit 0
elif [ "$MODS_VULNERABLE" = "0" ]; then
    ok "all primitives blacklisted or unavailable"
    exit 0
else
    bad "VULNERABLE: $MODS_VULNERABLE module(s) expose page-cache write primitives"
    bad "and unprivileged userns operations are NOT blocked by an LSM."
    if [ "$PAM_NULLOK" = "1" ]; then
        bad "  + pam_unix nullok is enabled — exploit can drop into root via su"
    fi
    echo ""
    info "Remediation options (pick one or combine):"
    info "  1. Apply your distro's kernel update with f4c50a4034e6 backport"
    info "     (best: fixes the bug at its source)"
    info "  2. Install + run \`dirtyfail --mitigate\` (blacklists modules,"
    info "     sets apparmor_restrict_unprivileged_userns=1)"
    info "  3. Manual: edit /etc/modprobe.d/ to add"
    info "       install algif_aead /bin/false"
    info "       install esp4 /bin/false"
    info "       install esp6 /bin/false"
    info "       install rxrpc /bin/false"
    info "     then \`sudo rmmod\` each + \`sudo sysctl vm.drop_caches=3\`."
    info "  4. Disable pam_unix nullok (removes the in-system su step that"
    info "     converts a page-cache STORE into a real root shell)."
    exit 1
fi
