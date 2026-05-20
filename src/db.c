#include "db.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>

static const char *SCHEMA =
    "CREATE TABLE IF NOT EXISTS users ("
    "  id           INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  username     TEXT    UNIQUE NOT NULL,"
    "  display_name TEXT    NOT NULL,"
    "  created_at   INTEGER NOT NULL"
    ");"
    "CREATE TABLE IF NOT EXISTS credentials ("
    "  id             INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  credential_id  BLOB    UNIQUE NOT NULL,"
    "  user_id        INTEGER NOT NULL REFERENCES users(id),"
    "  public_key_der BLOB    NOT NULL,"
    "  sign_count     INTEGER NOT NULL DEFAULT 0,"
    "  aaguid         BLOB,"
    "  created_at     INTEGER NOT NULL"
    ");"
    "CREATE TABLE IF NOT EXISTS challenges ("
    "  id         INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  challenge  BLOB    NOT NULL,"
    "  username   TEXT    NOT NULL,"
    "  type       TEXT    NOT NULL,"
    "  created_at INTEGER NOT NULL,"
    "  expires_at INTEGER NOT NULL"
    ");";

int db_init(db_ctx_t *ctx, const char *path) {
    if (sqlite3_open(path, &ctx->db) != SQLITE_OK) return -1;
    sqlite3_exec(ctx->db, "PRAGMA journal_mode=WAL;", NULL, NULL, NULL);
    char *err = NULL;
    int rc = sqlite3_exec(ctx->db, SCHEMA, NULL, NULL, &err);
    if (rc != SQLITE_OK) {
        sqlite3_free(err);
        return -1;
    }
    return 0;
}

void db_close(db_ctx_t *ctx) {
    sqlite3_close(ctx->db);
    ctx->db = NULL;
}

/* ---- Users -------------------------------------------------------------- */

int db_user_create(db_ctx_t *ctx, const char *username,
                   const char *display_name, int64_t *out_user_id) {
    const char *sql =
        "INSERT INTO users (username, display_name, created_at)"
        " VALUES (?, ?, ?)"
        " ON CONFLICT(username) DO UPDATE SET display_name=excluded.display_name"
        " RETURNING id;";
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(ctx->db, sql, -1, &stmt, NULL) != SQLITE_OK) return -1;

    sqlite3_bind_text(stmt, 1, username,     -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, display_name, -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 3, (int64_t)time(NULL));

    int rc = -1;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        if (out_user_id) *out_user_id = sqlite3_column_int64(stmt, 0);
        rc = 0;
    }
    sqlite3_finalize(stmt);
    return rc;
}

int db_user_find(db_ctx_t *ctx, const char *username, int64_t *out_user_id) {
    const char *sql = "SELECT id FROM users WHERE username = ?;";
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(ctx->db, sql, -1, &stmt, NULL) != SQLITE_OK) return -1;

    sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);

    int rc = -1;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        if (out_user_id) *out_user_id = sqlite3_column_int64(stmt, 0);
        rc = 0;
    }
    sqlite3_finalize(stmt);
    return rc;
}

int db_user_find_by_id(db_ctx_t *ctx, int64_t user_id,
                       char *out_username, size_t uname_cap) {
    const char *sql = "SELECT username FROM users WHERE id = ?;";
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(ctx->db, sql, -1, &stmt, NULL) != SQLITE_OK) return -1;

    sqlite3_bind_int64(stmt, 1, user_id);

    int rc = -1;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        const char *u = (const char *)sqlite3_column_text(stmt, 0);
        if (u && uname_cap > 0) {
            size_t copy = strlen(u) < uname_cap - 1 ? strlen(u) : uname_cap - 1;
            memcpy(out_username, u, copy);
            out_username[copy] = '\0';
        }
        rc = 0;
    }
    sqlite3_finalize(stmt);
    return rc;
}

/* ---- Credentials -------------------------------------------------------- */

int db_cred_store(db_ctx_t *ctx, int64_t user_id,
                  const uint8_t *cred_id,    size_t cred_id_len,
                  const uint8_t *pubkey_der, size_t pubkey_der_len,
                  uint32_t sign_count, const uint8_t aaguid[16]) {
    const char *sql =
        "INSERT OR IGNORE INTO credentials"
        " (credential_id, user_id, public_key_der, sign_count, aaguid, created_at)"
        " VALUES (?, ?, ?, ?, ?, ?);";
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(ctx->db, sql, -1, &stmt, NULL) != SQLITE_OK) return -1;

    sqlite3_bind_blob(stmt, 1, cred_id,    (int)cred_id_len,    SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 2, user_id);
    sqlite3_bind_blob(stmt, 3, pubkey_der, (int)pubkey_der_len, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 4, (int)sign_count);
    sqlite3_bind_blob(stmt, 5, aaguid, 16, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 6, (int64_t)time(NULL));

    int rc = sqlite3_step(stmt) == SQLITE_DONE ? 0 : -1;
    sqlite3_finalize(stmt);
    return rc;
}

int db_cred_find(db_ctx_t *ctx,
                 const uint8_t *cred_id, size_t cred_id_len,
                 int64_t *out_user_id,
                 uint8_t **out_pubkey_der, size_t *out_pubkey_len,
                 uint32_t *out_sign_count) {
    const char *sql =
        "SELECT user_id, public_key_der, sign_count FROM credentials"
        " WHERE credential_id = ?;";
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(ctx->db, sql, -1, &stmt, NULL) != SQLITE_OK) return -1;

    sqlite3_bind_blob(stmt, 1, cred_id, (int)cred_id_len, SQLITE_STATIC);

    int rc = -1;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        if (out_user_id)    *out_user_id    = sqlite3_column_int64(stmt, 0);
        if (out_sign_count) *out_sign_count = (uint32_t)sqlite3_column_int(stmt, 2);

        if (out_pubkey_der && out_pubkey_len) {
            const void *blob = sqlite3_column_blob(stmt, 1);
            int blob_len     = sqlite3_column_bytes(stmt, 1);
            *out_pubkey_der = malloc((size_t)blob_len);
            if (*out_pubkey_der) {
                memcpy(*out_pubkey_der, blob, (size_t)blob_len);
                *out_pubkey_len = (size_t)blob_len;
                rc = 0;
            }
        } else {
            rc = 0;
        }
    }
    sqlite3_finalize(stmt);
    return rc;
}

int db_cred_update_sign_count(db_ctx_t *ctx,
                              const uint8_t *cred_id, size_t cred_id_len,
                              uint32_t new_count) {
    const char *sql =
        "UPDATE credentials SET sign_count = ? WHERE credential_id = ?;";
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(ctx->db, sql, -1, &stmt, NULL) != SQLITE_OK) return -1;

    sqlite3_bind_int(stmt, 1, (int)new_count);
    sqlite3_bind_blob(stmt, 2, cred_id, (int)cred_id_len, SQLITE_STATIC);

    int rc = sqlite3_step(stmt) == SQLITE_DONE ? 0 : -1;
    sqlite3_finalize(stmt);
    return rc;
}

int db_creds_for_user(db_ctx_t *ctx, int64_t user_id,
                      db_cred_cb cb, void *userdata) {
    const char *sql =
        "SELECT credential_id FROM credentials WHERE user_id = ?;";
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(ctx->db, sql, -1, &stmt, NULL) != SQLITE_OK) return -1;

    sqlite3_bind_int64(stmt, 1, user_id);

    int count = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const void *blob = sqlite3_column_blob(stmt, 0);
        int blob_len     = sqlite3_column_bytes(stmt, 0);
        cb((const uint8_t *)blob, (size_t)blob_len, userdata);
        count++;
    }
    sqlite3_finalize(stmt);
    return count;
}

/* ---- Challenges --------------------------------------------------------- */

int db_challenge_store(db_ctx_t *ctx, const uint8_t challenge[32],
                       const char *username, const char *type,
                       int64_t expires_at) {
    const char *sql =
        "INSERT INTO challenges (challenge, username, type, created_at, expires_at)"
        " VALUES (?, ?, ?, ?, ?);";
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(ctx->db, sql, -1, &stmt, NULL) != SQLITE_OK) return -1;

    sqlite3_bind_blob(stmt, 1, challenge, 32, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, username, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, type,     -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 4, (int64_t)time(NULL));
    sqlite3_bind_int64(stmt, 5, expires_at);

    int rc = sqlite3_step(stmt) == SQLITE_DONE ? 0 : -1;
    sqlite3_finalize(stmt);
    return rc;
}

int db_challenge_consume(db_ctx_t *ctx, const uint8_t *challenge, size_t chal_len,
                         const char *type,
                         char *out_username, size_t uname_cap) {
    /* Find the challenge */
    const char *sel =
        "SELECT id, username, expires_at FROM challenges"
        " WHERE challenge = ? AND type = ?;";
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(ctx->db, sel, -1, &stmt, NULL) != SQLITE_OK) return -1;

    sqlite3_bind_blob(stmt, 1, challenge, (int)chal_len, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, type, -1, SQLITE_STATIC);

    int rc = -1;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        int64_t row_id    = sqlite3_column_int64(stmt, 0);
        const char *uname = (const char *)sqlite3_column_text(stmt, 1);
        int64_t expires   = sqlite3_column_int64(stmt, 2);

        if ((int64_t)time(NULL) <= expires && uname) {
            if (out_username && uname_cap > 0) {
                size_t copy = strlen(uname);
                if (copy >= uname_cap) copy = uname_cap - 1;
                memcpy(out_username, uname, copy);
                out_username[copy] = '\0';
            }
            rc = 0;

            /* Delete the challenge (one-time use) */
            const char *del = "DELETE FROM challenges WHERE id = ?;";
            sqlite3_stmt *del_stmt;
            if (sqlite3_prepare_v2(ctx->db, del, -1, &del_stmt, NULL) == SQLITE_OK) {
                sqlite3_bind_int64(del_stmt, 1, row_id);
                sqlite3_step(del_stmt);
                sqlite3_finalize(del_stmt);
            }
        }
    }
    sqlite3_finalize(stmt);
    return rc;
}
