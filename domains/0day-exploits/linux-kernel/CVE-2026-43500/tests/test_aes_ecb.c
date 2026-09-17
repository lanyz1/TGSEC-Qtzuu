/*
 * tests/test_aes_ecb.c
 *
 * Verifies that the kernel's AF_ALG `ecb(aes)` implementation produces
 * the expected outputs for known AES-128-ECB test vectors. This is the
 * primitive that copyfail_gcm.c uses to compute GCM keystream byte 0
 * via the J0+1 counter block trick.
 *
 * If this test passes, the GCM exploit's brute-force loop is sound.
 * If it fails, the kernel's AES implementation differs from spec — no
 * exploit will produce the right STORE values.
 *
 * Linux-only. Uses the same AF_ALG primitives as copyfail_gcm.c.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <linux/if_alg.h>

static int failures = 0;

#define ASSERT(cond, msg, ...) do { \
    if (!(cond)) { fprintf(stderr, "FAIL: " msg "\n", ##__VA_ARGS__); failures++; } \
    else        { fprintf(stderr, "  ok: " msg "\n", ##__VA_ARGS__); } \
} while (0)

static int alg_open_ecb_aes(const unsigned char key[16])
{
    int s = socket(AF_ALG, SOCK_SEQPACKET, 0);
    if (s < 0) return -1;
    struct sockaddr_alg sa = { .salg_family = AF_ALG };
    strcpy((char *)sa.salg_type, "skcipher");
    strcpy((char *)sa.salg_name, "ecb(aes)");
    if (bind(s, (struct sockaddr *)&sa, sizeof(sa)) < 0) { close(s); return -1; }
    if (setsockopt(s, SOL_ALG, ALG_SET_KEY, key, 16) < 0) { close(s); return -1; }
    return s;
}

static int aes_ecb_encrypt(int s, const unsigned char in[16], unsigned char out[16])
{
    int op = accept(s, NULL, NULL);
    if (op < 0) return -1;
    char cbuf[CMSG_SPACE(sizeof(int))] = {0};
    struct msghdr msg = { .msg_control = cbuf, .msg_controllen = sizeof(cbuf) };
    struct cmsghdr *c = CMSG_FIRSTHDR(&msg);
    c->cmsg_level = SOL_ALG; c->cmsg_type = ALG_SET_OP; c->cmsg_len = CMSG_LEN(sizeof(int));
    *(int *)CMSG_DATA(c) = ALG_OP_ENCRYPT;
    struct iovec iov = { .iov_base = (void *)in, .iov_len = 16 };
    msg.msg_iov = &iov; msg.msg_iovlen = 1;
    if (sendmsg(op, &msg, 0) != 16) { close(op); return -1; }
    int n = read(op, out, 16);
    close(op);
    return n == 16 ? 0 : -1;
}

int main(void)
{
    /* NIST test vector: AES-128 ECB
     *   key  = 000102030405060708090a0b0c0d0e0f
     *   pt   = 000102030405060708090a0b0c0d0e0f
     *   ct   = 0a940bb5416ef045f1c39458c653ea5a
     */
    unsigned char key[16], in[16], out[16];
    for (int i = 0; i < 16; i++) { key[i] = i; in[i] = i; }
    static const unsigned char expected[16] = {
        0x0a,0x94,0x0b,0xb5,0x41,0x6e,0xf0,0x45,
        0xf1,0xc3,0x94,0x58,0xc6,0x53,0xea,0x5a
    };

    int s = alg_open_ecb_aes(key);
    ASSERT(s >= 0, "AF_ALG skcipher ecb(aes) bindable + keyable");
    if (s < 0) return 1;

    ASSERT(aes_ecb_encrypt(s, in, out) == 0, "single-block ECB encrypt completes");

    ASSERT(memcmp(out, expected, 16) == 0,
           "ECB(K=0..15, P=0..15) = 0a940bb5416ef045f1c39458c653ea5a");
    if (memcmp(out, expected, 16) != 0) {
        fprintf(stderr, "    got: ");
        for (int i = 0; i < 16; i++) fprintf(stderr, "%02x", out[i]);
        fprintf(stderr, "\n");
    }

    /* GCM J0+1 counter block sanity: nonce(12) || 0x00000002. byte 0 of
     * the encrypted block is the keystream byte that XORs onto plaintext
     * byte 0 in GCM. We don't verify against a specific GCM vector here
     * (no canonical short test for this), just that the operation runs. */
    unsigned char counter[16];
    memset(counter, 0xab, 12);
    counter[12] = 0; counter[13] = 0; counter[14] = 0; counter[15] = 2;
    ASSERT(aes_ecb_encrypt(s, counter, out) == 0,
           "GCM J0+1 counter block encrypt (keystream byte computation)");

    close(s);
    fprintf(stderr, "\n%d failure(s)\n", failures);
    return failures > 0 ? 1 : 0;
}
