/*
 * DIRTYFAIL — common.h
 *
 * Shared declarations for the DIRTYFAIL detector + PoC binary.
 *
 * This file is intentionally light: AF_ALG / SOL_ALG constants that older
 * libcs do not export, log macros that respect --no-color, and the
 * type definitions used by every CVE module.
 */

#ifndef DIRTYFAIL_COMMON_H
#define DIRTYFAIL_COMMON_H

/* The Makefile passes -D_GNU_SOURCE on the command line; this guard
 * keeps gcc from warning about a duplicate definition when callers
 * include common.h after the cmdline -D has already taken effect. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

/* ------------------------------------------------------------------ *
 * AF_ALG constants
 *
 * These are upstream in <linux/if_alg.h>, but plenty of distros ship
 * stale headers. Declare locally so DIRTYFAIL builds on every target
 * we have run it against (Ubuntu 22.04 → 24.04, RHEL 9/10, Fedora 42+).
 * ------------------------------------------------------------------ */
#ifndef AF_ALG
#define AF_ALG 38
#endif
#ifndef SOL_ALG
#define SOL_ALG 279
#endif
#define ALG_SET_KEY                1
#define ALG_SET_IV                 2
#define ALG_SET_OP                 3
#define ALG_SET_AEAD_ASSOCLEN      4
#define ALG_SET_AEAD_AUTHSIZE      5
#define ALG_OP_DECRYPT             0
#define ALG_OP_ENCRYPT             1
#define CRYPTO_AUTHENC_KEYA_PARAM  1   /* rtattr type, <crypto/authenc.h> */

struct sockaddr_alg_compat {
    unsigned short  salg_family;
    unsigned char   salg_type[14];
    unsigned int    salg_feat;
    unsigned int    salg_mask;
    unsigned char   salg_name[64];
};

/* ------------------------------------------------------------------ *
 * Logging
 *
 * DIRTYFAIL output is meant to be skim-readable by a researcher *and*
 * grep-friendly in CI. We use a small set of fixed prefixes so that
 * automation can match on lines without parsing color escapes:
 *
 *   [*]  step / status     [+]  good news / detection result
 *   [-]  bad news          [!]  attention / VULNERABLE
 *   [i]  hint              [?]  prompt
 * ------------------------------------------------------------------ */
extern bool dirtyfail_use_color;

/* When true, --scan and --check-* modes do an active sentinel-file STORE
 * probe per mode in addition to precondition checks. Set by --active. */
extern bool dirtyfail_active_probes;

/* When true, --no-shell mode skips the auto-revert step — the page-cache
 * plant survives until --cleanup or drop_caches. Used by the
 * container-escape demo to show that the corruption crosses namespace
 * boundaries. Set by --no-revert. */
extern bool dirtyfail_no_revert;

/* When true, --scan emits a single JSON object on stdout (suitable for
 * SIEM/fleet ingestion); all log output (banner, step/ok/bad/warn/hint)
 * is redirected to stderr. Set by --json. */
extern bool dirtyfail_json;

void log_step (const char *fmt, ...) __attribute__((format(printf, 1, 2)));
void log_ok   (const char *fmt, ...) __attribute__((format(printf, 1, 2)));
void log_bad  (const char *fmt, ...) __attribute__((format(printf, 1, 2)));
void log_warn (const char *fmt, ...) __attribute__((format(printf, 1, 2)));
void log_hint (const char *fmt, ...) __attribute__((format(printf, 1, 2)));

/* ------------------------------------------------------------------ *
 * Result codes returned by every detector / exploiter.
 *
 * They map onto exit codes used by the top-level binary so that CI
 * pipelines can branch on them without parsing stdout:
 *
 *   DF_OK              exit 0   not vulnerable
 *   DF_VULNERABLE      exit 2   vulnerable (detector confirmed primitive)
 *   DF_PRECOND_FAIL    exit 0   prerequisites missing → not vulnerable here
 *   DF_TEST_ERROR      exit 1   could not determine
 *   DF_EXPLOIT_OK      exit 0   exploit succeeded (root achieved)
 *   DF_EXPLOIT_FAIL    exit 3   exploit attempted but did not land
 *
 * Detectors should never return DF_EXPLOIT_*; exploiters should never
 * return DF_PRECOND_FAIL (they assume the detector ran first).
 * ------------------------------------------------------------------ */
typedef enum {
    DF_OK            = 0,
    DF_VULNERABLE    = 2,
    DF_PRECOND_FAIL  = 4,
    DF_TEST_ERROR    = 1,
    DF_EXPLOIT_OK    = 5,
    DF_EXPLOIT_FAIL  = 3,
} df_result_t;

/* ------------------------------------------------------------------ *
 * Utilities (common.c)
 * ------------------------------------------------------------------ */

/* Parse uname(2)->release into (major, minor). Returns false on parse error. */
bool kernel_version(int *major, int *minor);

/* Read /proc/modules and return true if `name` is loaded. Returns false
 * (and sets errno) if /proc/modules cannot be opened. */
bool kmod_loaded(const char *name);

/* Best-effort: can the calling user create a user namespace?
 *   forks a child that calls unshare(CLONE_NEWUSER) and reports back. */
bool unprivileged_userns_allowed(void);

/* Find current user's UID/GID field offsets in /etc/passwd.
 *   uid_off, uid_len:  byte offset and string length of UID field
 *   uid_str:           caller-supplied buffer >= 16 bytes; receives current UID
 * Returns false if user not found or UID isn't a 4-digit number. */
bool find_passwd_uid_field(const char *username,
                           off_t *uid_off, size_t *uid_len,
                           char *uid_str);

/* Drop the kernel page cache. Requires root. */
bool drop_caches(void);

/* Best-effort eviction of /etc/passwd from page cache. Tries
 * POSIX_FADV_DONTNEED, then `sudo drop_caches` as belt-and-suspenders.
 * Returns true if at least one path succeeded. See common.c for
 * caveats. */
bool try_revert_passwd_page_cache(void);

/* Print a hex+ASCII dump (max `len` bytes). For debug output. */
void hex_dump(const unsigned char *buf, size_t len);

/* Build the rtattr-prefixed authenc keyblob expected by ALG_SET_KEY for
 * authencesn(hmac(sha256), cbc(aes)). `out` must be >= 8+authkeylen+enckeylen.
 * Returns total bytes written. */
size_t build_authenc_keyblob(unsigned char *out,
                             const unsigned char *authkey, size_t authkeylen,
                             const unsigned char *enckey,  size_t enckeylen);

/* Prompt the user to type the literal string `expected` and press enter.
 * Returns true only on exact match. Used as a last-line gate before
 * --exploit modifies real system state. */
bool typed_confirm(const char *expected);

/* Convenience: open `path` RO and return a freshly-cached fd.
 * The page-cache primitives below all assume the page is hot. */
int open_and_cache(const char *path);

/* Return the user's real (outer) uid, defeating the userns illusion.
 *
 * After the AppArmor bypass enters us into a fresh user namespace with
 * uid_map "0 <real_uid> 1", `getuid()` returns 0 inside the namespace —
 * which lies to exploit code that wants to know which user account to
 * target in /etc/passwd. This helper reads /proc/self/uid_map; if it
 * shows a non-identity mapping like "0 1000 1", returns the outer uid
 * (1000). Otherwise (init namespace, or no userns at all) returns
 * `getuid()`.
 *
 * Same idea for real_gid_for_target. */
uid_t real_uid_for_target(void);
gid_t real_gid_for_target(void);

/* If $SSH_CONNECTION is set AND `target_user` is the SSH login user,
 * the user-uid-flip exploits about to fire will lock the operator out
 * of SSH (sshd reads modified /etc/passwd, sees uid 0, then StrictModes
 * rejects ~/.ssh/authorized_keys because file owner != logging-in uid).
 * The lockout persists until the page cache is evicted — typically only
 * a reboot recovers, since drop_caches needs root.
 *
 * Emit a loud warning and require an extra typed_confirm("YES_BREAK_SSH").
 * Returns true to proceed, false to abort. Always returns true when not
 * over SSH or when the target user differs from $USER. */
bool ssh_lockout_check(const char *target_user);

#endif /* DIRTYFAIL_COMMON_H */
