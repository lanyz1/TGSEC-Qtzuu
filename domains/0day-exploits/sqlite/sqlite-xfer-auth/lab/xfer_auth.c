/* SQLite 3.53.4 xferOptimization skips source SQLITE_SELECT / SQLITE_READ. */
#define _GNU_SOURCE

#include "sqlite3.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define LABEL "sqlite-xfer-auth"
#define WITNESS "SQLITE-XFER-AUTH-WITNESS"
#define EXPECT_VERSION "3.53.4"
#define EXPECT_SOURCE_ID \
    "2026-07-24 19:02:57 bf7c7f30031888f4e796e429ab3978879485813aaca6f641c7b33e4e09459bcc"
#define LISTEN_HOST "0.0.0.0"
#define DEFAULT_PORT 18850
#define MAX_AUTH_EVENTS 32
#define AUTH_EVENT_LEN 96

typedef struct {
    char events[MAX_AUTH_EVENTS][AUTH_EVENT_LEN];
    int n_events;
    int n_select;
    int n_read_src;
    int n_insert_dest;
    int n_insert_other;
    int n_deny;
} AuthLog;

static const char *action_name(int action) {
    switch (action) {
        case SQLITE_CREATE_INDEX:
            return "CREATE_INDEX";
        case SQLITE_CREATE_TABLE:
            return "CREATE_TABLE";
        case SQLITE_DELETE:
            return "DELETE";
        case SQLITE_DROP_TABLE:
            return "DROP_TABLE";
        case SQLITE_INSERT:
            return "INSERT";
        case SQLITE_PRAGMA:
            return "PRAGMA";
        case SQLITE_READ:
            return "READ";
        case SQLITE_SELECT:
            return "SELECT";
        case SQLITE_TRANSACTION:
            return "TRANSACTION";
        case SQLITE_UPDATE:
            return "UPDATE";
        case SQLITE_FUNCTION:
            return "FUNCTION";
        case SQLITE_RECURSIVE:
            return "RECURSIVE";
        default:
            return "OTHER";
    }
}

static int same_ident(const char *left, const char *right) {
    if (left == NULL || right == NULL) {
        return 0;
    }
    return sqlite3_stricmp(left, right) == 0;
}

static void record_event(AuthLog *log, int action, const char *a3, const char *a4) {
    if (log == NULL || log->n_events >= MAX_AUTH_EVENTS) {
        return;
    }
    snprintf(
        log->events[log->n_events],
        AUTH_EVENT_LEN,
        "%s:%s.%s",
        action_name(action),
        a3 != NULL ? a3 : "",
        a4 != NULL ? a4 : ""
    );
    log->n_events++;
}

static int authorizer(
    void *udp,
    int action,
    const char *a3,
    const char *a4,
    const char *a5,
    const char *a6
) {
    AuthLog *log = udp;
    int deny = 0;

    (void)a5;
    (void)a6;
    record_event(log, action, a3, a4);

    if (action == SQLITE_SELECT) {
        log->n_select++;
        deny = 1;
    } else if (action == SQLITE_READ && same_ident(a3, "src")) {
        log->n_read_src++;
        deny = 1;
    } else if (action == SQLITE_INSERT && same_ident(a3, "dest")) {
        log->n_insert_dest++;
    } else if (action == SQLITE_INSERT) {
        log->n_insert_other++;
        deny = 1;
    }

    if (deny) {
        log->n_deny++;
        return SQLITE_DENY;
    }
    return SQLITE_OK;
}

static void json_str(FILE *out, const char *value) {
    fputc('"', out);
    if (value != NULL) {
        for (const unsigned char *p = (const unsigned char *)value; *p != '\0'; p++) {
            if (*p == '"' || *p == '\\') {
                fputc('\\', out);
                fputc((int)*p, out);
            } else if (*p == '\n') {
                fputs("\\n", out);
            } else if (*p == '\r') {
                fputs("\\r", out);
            } else if (*p == '\t') {
                fputs("\\t", out);
            } else if (*p < 0x20) {
                fprintf(out, "\\u%04x", *p);
            } else {
                fputc((int)*p, out);
            }
        }
    }
    fputc('"', out);
}

static void json_events(FILE *out, const AuthLog *log) {
    fputc('[', out);
    for (int i = 0; i < log->n_events; i++) {
        if (i > 0) {
            fputc(',', out);
        }
        json_str(out, log->events[i]);
    }
    fputc(']', out);
}

static int exec_sql(sqlite3 *db, const char *sql, char **errmsg) {
    char *err = NULL;
    int rc = sqlite3_exec(db, sql, NULL, NULL, &err);
    if (errmsg != NULL) {
        *errmsg = err;
    } else if (err != NULL) {
        sqlite3_free(err);
    }
    return rc;
}

static char *run_proof(void) {
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    AuthLog select_log;
    AuthLog insert_log;
    char *body = NULL;
    size_t body_len = 0;
    FILE *out = NULL;
    char seed_sql[256];
    int rc;
    int select_rc = -1;
    int insert_rc = -1;
    int insert_step = -1;
    int dest_rc = -1;
    const char *select_err = "";
    const char *insert_err = "";
    const char *dest_err = "";
    const char *dest_value = "";
    int select_denied = 0;
    int insert_ok = 0;
    int dest_has_witness = 0;
    int version_ok = 0;
    int sourceid_ok = 0;
    const char *how = "incomplete";
    const char *libversion = sqlite3_libversion();
    const char *sourceid = sqlite3_sourceid();

    memset(&select_log, 0, sizeof(select_log));
    memset(&insert_log, 0, sizeof(insert_log));

    version_ok = libversion != NULL && strcmp(libversion, EXPECT_VERSION) == 0;
    sourceid_ok = sourceid != NULL && strstr(sourceid, EXPECT_SOURCE_ID) != NULL;

    rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) {
        const char *open_err = db != NULL ? sqlite3_errmsg(db) : sqlite3_errstr(rc);
        out = open_memstream(&body, &body_len);
        if (out == NULL) {
            if (db != NULL) {
                sqlite3_close(db);
            }
            return NULL;
        }
        fprintf(out, "{\"ok\":false,\"error\":");
        json_str(out, open_err);
        fputc('}', out);
        fclose(out);
        if (db != NULL) {
            sqlite3_close(db);
        }
        return body;
    }

    rc = exec_sql(db, "CREATE TABLE src(a); CREATE TABLE dest(a);", NULL);
    if (rc == SQLITE_OK) {
        snprintf(seed_sql, sizeof(seed_sql), "INSERT INTO src VALUES('%s');", WITNESS);
        rc = exec_sql(db, seed_sql, NULL);
    }
    if (rc != SQLITE_OK) {
        out = open_memstream(&body, &body_len);
        if (out == NULL) {
            sqlite3_close(db);
            return NULL;
        }
        fprintf(out, "{\"ok\":false,\"error\":");
        json_str(out, sqlite3_errmsg(db));
        fputc('}', out);
        fclose(out);
        sqlite3_close(db);
        return body;
    }

    sqlite3_set_authorizer(db, authorizer, &select_log);
    select_rc = sqlite3_prepare_v2(db, "SELECT * FROM src", -1, &stmt, NULL);
    select_err = sqlite3_errmsg(db);
    select_denied = (select_rc == SQLITE_AUTH);
    if (stmt != NULL) {
        sqlite3_finalize(stmt);
        stmt = NULL;
    }

    sqlite3_set_authorizer(db, authorizer, &insert_log);
    insert_rc = sqlite3_prepare_v2(db, "INSERT INTO dest SELECT * FROM src", -1, &stmt, NULL);
    insert_err = sqlite3_errmsg(db);
    if (insert_rc == SQLITE_OK && stmt != NULL) {
        insert_step = sqlite3_step(stmt);
        if (insert_step != SQLITE_DONE) {
            insert_err = sqlite3_errmsg(db);
        }
    }
    if (stmt != NULL) {
        sqlite3_finalize(stmt);
        stmt = NULL;
    }
    insert_ok = (insert_rc == SQLITE_OK && insert_step == SQLITE_DONE);

    sqlite3_set_authorizer(db, NULL, NULL);
    dest_rc = sqlite3_prepare_v2(db, "SELECT a FROM dest", -1, &stmt, NULL);
    dest_err = sqlite3_errmsg(db);
    if (dest_rc == SQLITE_OK && stmt != NULL && sqlite3_step(stmt) == SQLITE_ROW) {
        const unsigned char *text = sqlite3_column_text(stmt, 0);
        if (text != NULL) {
            dest_value = (const char *)text;
            dest_has_witness = strcmp(dest_value, WITNESS) == 0;
        }
    }

    if (!version_ok || !sourceid_ok) {
        how = "pin-mismatch";
    } else if (!select_denied) {
        how = "select-src-not-denied";
    } else if (!insert_ok) {
        how = "insert-denied";
    } else if (!dest_has_witness) {
        how = "dest-missing-witness";
    } else if (insert_log.n_select != 0 || insert_log.n_read_src != 0) {
        how = "src-auth-still-fired";
    } else {
        how = "xfer-opt-skip-src-read";
    }

    out = open_memstream(&body, &body_len);
    if (out == NULL) {
        if (stmt != NULL) {
            sqlite3_finalize(stmt);
        }
        sqlite3_close(db);
        return NULL;
    }

    fprintf(out, "{");
    fprintf(out, "\"ok\":%s,", dest_has_witness && select_denied && insert_ok ? "true" : "false");
    fprintf(out, "\"label\":\"%s\",", LABEL);
    fprintf(out, "\"witness\":\"%s\",", WITNESS);
    fprintf(out, "\"libversion\":");
    json_str(out, libversion);
    fprintf(out, ",\"sourceid\":");
    json_str(out, sourceid);
    fprintf(out, ",\"version_ok\":%s,", version_ok ? "true" : "false");
    fprintf(out, "\"sourceid_ok\":%s,", sourceid_ok ? "true" : "false");
    fprintf(out, "\"select_src_rc\":%d,", select_rc);
    fprintf(out, "\"select_src_errmsg\":");
    json_str(out, select_err);
    fprintf(out, ",\"select_src_denied\":%s,", select_denied ? "true" : "false");
    fprintf(out, "\"select_actions\":");
    json_events(out, &select_log);
    fprintf(out, ",\"insert_select_rc\":%d,", insert_rc);
    fprintf(out, "\"insert_select_step\":%d,", insert_step);
    fprintf(out, "\"insert_select_errmsg\":");
    json_str(out, insert_err);
    fprintf(out, ",\"insert_select_ok\":%s,", insert_ok ? "true" : "false");
    fprintf(out, "\"insert_n_select\":%d,", insert_log.n_select);
    fprintf(out, "\"insert_n_read_src\":%d,", insert_log.n_read_src);
    fprintf(out, "\"insert_n_insert_dest\":%d,", insert_log.n_insert_dest);
    fprintf(out, "\"insert_actions\":");
    json_events(out, &insert_log);
    fprintf(out, ",\"dest_rc\":%d,", dest_rc);
    fprintf(out, "\"dest_errmsg\":");
    json_str(out, dest_err);
    fprintf(out, ",\"dest_value\":");
    json_str(out, dest_value);
    fprintf(out, ",\"dest_has_witness\":%s,", dest_has_witness ? "true" : "false");
    fprintf(out, "\"how\":");
    json_str(out, how);
    fprintf(out, "}");
    fclose(out);

    if (stmt != NULL) {
        sqlite3_finalize(stmt);
    }
    sqlite3_close(db);
    return body;
}

static int listen_http(int port) {
    int fd;
    int on = 1;
    struct sockaddr_in addr;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        return 1;
    }
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) != 0) {
        perror("setsockopt");
        close(fd);
        return 1;
    }
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons((uint16_t)port);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        perror("bind");
        close(fd);
        return 1;
    }
    if (listen(fd, 16) != 0) {
        perror("listen");
        close(fd);
        return 1;
    }

    fprintf(stdout, "listening %s:%d libversion=%s\n", LISTEN_HOST, port, sqlite3_libversion());
    fprintf(stdout, "sourceid=%s\n", sqlite3_sourceid());
    fflush(stdout);

    for (;;) {
        int client = accept(fd, NULL, NULL);
        char req[1024];
        char *body;
        char hdr[160];
        ssize_t nread;

        if (client < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("accept");
            close(fd);
            return 1;
        }
        nread = recv(client, req, sizeof(req) - 1, 0);
        if (nread < 0) {
            close(client);
            continue;
        }
        req[nread] = '\0';
        body = run_proof();
        if (body == NULL) {
            const char *fail = "{\"ok\":false,\"error\":\"proof-alloc\"}";
            snprintf(
                hdr,
                sizeof(hdr),
                "HTTP/1.1 500 Internal Server Error\r\n"
                "Content-Type: application/json\r\n"
                "Content-Length: %zu\r\n"
                "Connection: close\r\n"
                "\r\n",
                strlen(fail)
            );
            send(client, hdr, strlen(hdr), 0);
            send(client, fail, strlen(fail), 0);
            close(client);
            continue;
        }
        snprintf(
            hdr,
            sizeof(hdr),
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: application/json\r\n"
            "Content-Length: %zu\r\n"
            "Connection: close\r\n"
            "\r\n",
            strlen(body)
        );
        send(client, hdr, strlen(hdr), 0);
        send(client, body, strlen(body), 0);
        free(body);
        close(client);
    }
}

int main(int argc, char **argv) {
    int port = DEFAULT_PORT;
    const char *env_port = getenv("PORT");

    signal(SIGPIPE, SIG_IGN);
    if (env_port != NULL && env_port[0] != '\0') {
        port = atoi(env_port);
    }
    if (argc > 1 && strcmp(argv[1], "--once") == 0) {
        char *body = run_proof();
        if (body == NULL) {
            fprintf(stderr, "{\"ok\":false,\"error\":\"proof-alloc\"}\n");
            return 1;
        }
        fputs(body, stdout);
        fputc('\n', stdout);
        free(body);
        return 0;
    }
    if (argc > 2 && strcmp(argv[1], "--port") == 0) {
        port = atoi(argv[2]);
    }
    if (port <= 0 || port > 65535) {
        fprintf(stderr, "invalid-port\n");
        return 1;
    }
    return listen_http(port);
}
