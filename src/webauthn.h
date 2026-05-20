#pragma once
#include "db.h"
#include "cJSON.h"

#define RP_ID    "localhost"
#define RP_NAME  "C Passkey Demo"
#define ORIGIN   "http://localhost:8080"
#define CHAL_TTL 300   /* seconds */

/* Returns a cJSON* options object (caller must cJSON_Delete).
   Returns NULL on error. */
cJSON *webauthn_begin_registration(db_ctx_t *db, const char *username);
cJSON *webauthn_begin_authentication(db_ctx_t *db, const char *username);

/* Returns 0 on success, -1 on failure (err_out filled). */
int    webauthn_verify_registration(db_ctx_t *db, cJSON *credential,
                                    char *err_out, size_t err_cap);

/* Returns heap-allocated username on success (caller must free()), NULL on failure. */
char  *webauthn_verify_authentication(db_ctx_t *db, cJSON *assertion,
                                      char *err_out, size_t err_cap);
