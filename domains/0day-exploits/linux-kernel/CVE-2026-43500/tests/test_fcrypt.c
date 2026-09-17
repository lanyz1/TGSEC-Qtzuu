/*
 * tests/test_fcrypt.c
 *
 * Selftest for the rxkad fcrypt cipher implementation in src/fcrypt.c.
 * Built standalone via `make test`. No DIRTYFAIL runtime needed.
 *
 * Verifies:
 *  - All-zero key vector (catches gross structural bugs)
 *  - Non-zero key vector from kernel testmgr.h (catches subtle bugs
 *    in 7-bit packing or 11-bit ROR key schedule)
 *  - Brute-force harness convergence (sanity-checks predicate gating)
 */

#include "../src/fcrypt.h"
#include "../src/common.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

static int failures = 0;

#define ASSERT(cond, msg, ...) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL: " msg "\n", ##__VA_ARGS__); \
        failures++; \
    } else { \
        fprintf(stderr, "  ok: " msg "\n", ##__VA_ARGS__); \
    } \
} while (0)

static bool predicate_match_first_byte(const uint8_t p[8])
{
    return p[0] == 0xAB;
}

int main(void)
{
    fcrypt_init();

    /* Selftest covers both vectors. */
    ASSERT(fcrypt_selftest(),
           "fcrypt_selftest passes (covers k=0 and k=1144...66 vectors)");

    /* Spot-check vector 1 directly */
    fcrypt_ctx ctx;
    uint8_t out[8];
    static const uint8_t k1[8] = {0,0,0,0,0,0,0,0};
    static const uint8_t c1[8] = {0x0E,0x09,0x00,0xC7,0x3E,0xF7,0xED,0x41};
    fcrypt_setkey(&ctx, k1);
    fcrypt_decrypt(&ctx, out, c1);
    ASSERT(memcmp(out, "\x00\x00\x00\x00\x00\x00\x00\x00", 8) == 0,
           "vector 1: decrypt(k=0, ct=0E0900C73EF7ED41) = 0000000000000000");

    /* Spot-check vector 2 directly */
    static const uint8_t k2[8] = {0x11,0x44,0x77,0xAA,0xDD,0x00,0x33,0x66};
    static const uint8_t c2[8] = {0xD8,0xED,0x78,0x74,0x77,0xEC,0x06,0x80};
    static const uint8_t p2[8] = {0x12,0x34,0x56,0x78,0x9A,0xBC,0xDE,0xF0};
    fcrypt_setkey(&ctx, k2);
    fcrypt_decrypt(&ctx, out, c2);
    ASSERT(memcmp(out, p2, 8) == 0,
           "vector 2: decrypt(k=11447 7AAD D003 366, ct=D8ED787477EC0680) = 123456789ABCDEF0");

    /* Brute-force smoke test: search for K such that decrypt(C=0..7) starts with 0xAB.
     * Predicate hit rate = 1/256, so ~256 iters expected. Hard cap at 1<<20. */
    uint8_t key_out[8], pt_out[8];
    static const uint8_t test_ct[8] = {0,1,2,3,4,5,6,7};
    bool found = fcrypt_brute_force(test_ct, predicate_match_first_byte,
                                    1 << 20, (uint64_t)time(NULL),
                                    "smoke", key_out, pt_out);
    ASSERT(found,
           "brute force converges on first-byte=0xAB predicate within 1M iters");
    if (found) {
        /* Verify the discovered key actually produces the claimed plaintext */
        fcrypt_setkey(&ctx, key_out);
        fcrypt_decrypt(&ctx, out, test_ct);
        ASSERT(memcmp(out, pt_out, 8) == 0 && out[0] == 0xAB,
               "discovered key produces claimed plaintext (roundtrip OK)");
    }

    fprintf(stderr, "\n%d failure(s)\n", failures);
    return failures > 0 ? 1 : 0;
}
