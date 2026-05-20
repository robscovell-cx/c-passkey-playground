#pragma once
#include <stdint.h>
#include <stddef.h>
#include "sqlite3.h"

typedef struct {
    sqlite3 *db;
} db_ctx_t;

int  db_init(db_ctx_t *ctx, const char *path);
void db_close(db_ctx_t *ctx);

/* Users */
int db_user_create(db_ctx_t *ctx, const char *username,
                   const char *display_name, int64_t *out_user_id);
int db_user_find(db_ctx_t *ctx, const char *username, int64_t *out_user_id);

/* Credentials
   db_cred_find: out_pubkey_der is heap-allocated — caller must free(). */
int db_cred_store(db_ctx_t *ctx, int64_t user_id,
                  const uint8_t *cred_id,    size_t cred_id_len,
                  const uint8_t *pubkey_der, size_t pubkey_der_len,
                  uint32_t sign_count, const uint8_t aaguid[16]);
int db_cred_find(db_ctx_t *ctx,
                 const uint8_t *cred_id, size_t cred_id_len,
                 int64_t *out_user_id,
                 uint8_t **out_pubkey_der, size_t *out_pubkey_len,
                 uint32_t *out_sign_count);
int db_cred_update_sign_count(db_ctx_t *ctx,
                              const uint8_t *cred_id, size_t cred_id_len,
                              uint32_t new_count);

/* Iterate credentials belonging to a user (for allowCredentials list) */
typedef void (*db_cred_cb)(const uint8_t *cred_id, size_t len, void *ud);
int db_creds_for_user(db_ctx_t *ctx, int64_t user_id,
                      db_cred_cb cb, void *userdata);

/* Challenges */
int db_challenge_store(db_ctx_t *ctx, const uint8_t challenge[32],
                       const char *username, const char *type,
                       int64_t expires_at);

/* Consume (find + delete) a challenge. Fills out_username (NUL-terminated).
   Returns 0 if found and not expired, -1 otherwise. */
int db_challenge_consume(db_ctx_t *ctx, const uint8_t *challenge, size_t chal_len,
                         const char *type,
                         char *out_username, size_t uname_cap);
