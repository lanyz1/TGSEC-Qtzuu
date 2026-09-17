/*
 * DIRTYFAIL — mitigate.h
 *
 * Defensive companion to the exploit modes: applies all known
 * mitigations for Copy Fail / Dirty Frag in one shot. Intended for
 * sysadmins who want a fast "fix this until the kernel patch lands"
 * deployment.
 *
 * What `--mitigate` does:
 *
 *   1. Writes /etc/modprobe.d/dirtyfail-mitigations.conf with
 *      `install <mod> /bin/false` blacklists for:
 *        - algif_aead   (Copy Fail authencesn primitive)
 *        - esp4 + esp6  (Dirty Frag xfrm-ESP path)
 *        - rxrpc        (Dirty Frag RxRPC path)
 *
 *   2. rmmods any of those that are currently loaded.
 *
 *   3. Sets `kernel.apparmor_restrict_unprivileged_userns=1` (where
 *      AppArmor is loaded). Persists via /etc/sysctl.d/.
 *
 *   4. Drops the page cache to evict any pre-existing page-cache
 *      modifications.
 *
 *   5. Reports what it did so the operator can audit / undo.
 *
 * Caveats:
 *   - Requires root.
 *   - Disabling esp4/esp6 breaks IPsec / strongSwan.
 *   - Disabling rxrpc breaks AFS clients.
 *   - These are interim mitigations; the right fix is the kernel patch.
 *
 * Run with `--cleanup-mitigate` to undo (removes the blacklist conf,
 * removes the sysctl conf, but does not unload modules — operator
 * decides if/when to reload).
 */

#ifndef DIRTYFAIL_MITIGATE_H
#define DIRTYFAIL_MITIGATE_H

#include "common.h"

df_result_t mitigate_apply(void);
df_result_t mitigate_revert(void);

#endif
