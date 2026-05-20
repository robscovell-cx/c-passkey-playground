#include "webauthn.h"
#include "crypto.h"
#include "cbor.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdio.h>

/* Mongoose provides mg_random for generating random bytes */
#include "mongoose.h"

/* ---- Helpers ------------------------------------------------------------ */

static uint32_t be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16)
         | ((uint32_t)p[2] <<  8) |  (uint32_t)p[3];
}

static uint16_t be16(const uint8_t *p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

/* Base64url-encode bytes into a new heap string. Caller must free(). */
static char *b64url_new(const uint8_t *in, size_t in_len) {
    size_t cap = ((in_len + 2) / 3) * 4 + 1;
    char *out = malloc(cap);
    if (!out) return NULL;
    base64url_encode(in, in_len, out, cap);
    return out;
}

#define ERR(fmt, ...) \
    do { if (err_out && err_cap > 0) \
         snprintf(err_out, err_cap, fmt, ##__VA_ARGS__); } while (0)

/* ---- Registration: begin ------------------------------------------------ */

cJSON *webauthn_begin_registration(db_ctx_t *db, const char *username) {
    uint8_t challenge[32];
    mg_random(challenge, sizeof(challenge));

    if (db_challenge_store(db, challenge, username, "registration",
                           (int64_t)time(NULL) + CHAL_TTL) != 0)
        return NULL;

    char *chal_b64 = b64url_new(challenge, sizeof(challenge));
    char *user_b64 = b64url_new((const uint8_t *)username, strlen(username));
    if (!chal_b64 || !user_b64) { free(chal_b64); free(user_b64); return NULL; }

    cJSON *opts = cJSON_CreateObject();
    cJSON_AddStringToObject(opts, "challenge", chal_b64);

    cJSON *rp = cJSON_CreateObject();
    cJSON_AddStringToObject(rp, "id",   RP_ID);
    cJSON_AddStringToObject(rp, "name", RP_NAME);
    cJSON_AddItemToObject(opts, "rp", rp);

    cJSON *user = cJSON_CreateObject();
    cJSON_AddStringToObject(user, "id",          user_b64);
    cJSON_AddStringToObject(user, "name",        username);
    cJSON_AddStringToObject(user, "displayName", username);
    cJSON_AddItemToObject(opts, "user", user);

    cJSON *params = cJSON_CreateArray();
    cJSON *es256  = cJSON_CreateObject();
    cJSON_AddStringToObject(es256, "type", "public-key");
    cJSON_AddNumberToObject(es256, "alg",  -7);
    cJSON_AddItemToArray(params, es256);
    cJSON_AddItemToObject(opts, "pubKeyCredParams", params);

    cJSON_AddNumberToObject(opts, "timeout", 60000);
    cJSON_AddStringToObject(opts, "attestation", "none");

    cJSON *sel = cJSON_CreateObject();
    cJSON_AddStringToObject(sel, "userVerification", "preferred");
    cJSON_AddItemToObject(opts, "authenticatorSelection", sel);

    free(chal_b64);
    free(user_b64);
    return opts;
}

/* ---- Registration: verify ----------------------------------------------- */

int webauthn_verify_registration(db_ctx_t *db, cJSON *credential,
                                 char *err_out, size_t err_cap) {
    /* Extract nested fields */
    cJSON *resp = cJSON_GetObjectItemCaseSensitive(credential, "response");
    if (!cJSON_IsObject(resp)) { ERR("missing response"); return -1; }

    cJSON *cdj_b64 = cJSON_GetObjectItemCaseSensitive(resp, "clientDataJSON");
    cJSON *att_b64 = cJSON_GetObjectItemCaseSensitive(resp, "attestationObject");
    if (!cJSON_IsString(cdj_b64) || !cJSON_IsString(att_b64)) {
        ERR("missing clientDataJSON or attestationObject"); return -1;
    }

    /* --- Decode clientDataJSON --- */
    const char *cdj_str = cdj_b64->valuestring;
    size_t cdj_raw_len  = strlen(cdj_str) * 3 / 4 + 4;
    uint8_t *cdj_raw    = malloc(cdj_raw_len);
    if (!cdj_raw) { ERR("oom"); return -1; }

    if (base64url_decode(cdj_str, strlen(cdj_str), cdj_raw, &cdj_raw_len) != 0) {
        free(cdj_raw); ERR("bad clientDataJSON b64"); return -1;
    }

    /* NUL-terminate for JSON parsing */
    uint8_t *cdj_buf = realloc(cdj_raw, cdj_raw_len + 1);
    if (!cdj_buf) { free(cdj_raw); ERR("oom"); return -1; }
    cdj_buf[cdj_raw_len] = '\0';

    cJSON *cdj = cJSON_ParseWithLength((char *)cdj_buf, cdj_raw_len);
    if (!cdj) { free(cdj_buf); ERR("clientDataJSON parse failed"); return -1; }

    /* Verify type */
    cJSON *type = cJSON_GetObjectItemCaseSensitive(cdj, "type");
    if (!cJSON_IsString(type) || strcmp(type->valuestring, "webauthn.create") != 0) {
        cJSON_Delete(cdj); free(cdj_buf);
        ERR("wrong clientDataJSON type"); return -1;
    }

    /* Verify origin */
    cJSON *origin = cJSON_GetObjectItemCaseSensitive(cdj, "origin");
    if (!cJSON_IsString(origin) || strcmp(origin->valuestring, ORIGIN) != 0) {
        cJSON_Delete(cdj); free(cdj_buf);
        ERR("origin mismatch: got %s", origin ? origin->valuestring : "null");
        return -1;
    }

    /* Verify challenge: decode b64url and compare to DB */
    cJSON *chal_json = cJSON_GetObjectItemCaseSensitive(cdj, "challenge");
    if (!cJSON_IsString(chal_json)) {
        cJSON_Delete(cdj); free(cdj_buf); ERR("missing challenge"); return -1;
    }
    uint8_t chal_bytes[64];
    size_t  chal_len = sizeof(chal_bytes);
    if (base64url_decode(chal_json->valuestring, strlen(chal_json->valuestring),
                         chal_bytes, &chal_len) != 0 || chal_len != 32) {
        cJSON_Delete(cdj); free(cdj_buf); ERR("bad challenge b64"); return -1;
    }

    char username[256] = {0};
    if (db_challenge_consume(db, chal_bytes, 32, "registration",
                             username, sizeof(username)) != 0) {
        cJSON_Delete(cdj); free(cdj_buf);
        ERR("challenge not found or expired"); return -1;
    }
    cJSON_Delete(cdj);

    /* --- Decode attestationObject --- */
    const char *att_str = att_b64->valuestring;
    size_t att_len      = strlen(att_str) * 3 / 4 + 4;
    uint8_t *att_buf    = malloc(att_len);
    if (!att_buf) { free(cdj_buf); ERR("oom"); return -1; }

    if (base64url_decode(att_str, strlen(att_str), att_buf, &att_len) != 0) {
        free(att_buf); free(cdj_buf); ERR("bad attestationObject b64"); return -1;
    }

    const uint8_t *auth_data;
    size_t         auth_data_len;
    char           fmt[32];
    if (cbor_parse_attestation_object(att_buf, att_len,
                                      &auth_data, &auth_data_len,
                                      fmt, sizeof(fmt)) != 0) {
        free(att_buf); free(cdj_buf); ERR("CBOR parse failed"); return -1;
    }

    /* --- Parse authData --- */
    if (auth_data_len < 55) {
        free(att_buf); free(cdj_buf); ERR("authData too short"); return -1;
    }

    /* Verify rpIdHash */
    uint8_t rp_hash[32];
    sha256((const uint8_t *)RP_ID, strlen(RP_ID), rp_hash);
    if (memcmp(auth_data, rp_hash, 32) != 0) {
        free(att_buf); free(cdj_buf); ERR("rpIdHash mismatch"); return -1;
    }

    uint8_t flags       = auth_data[32];
    uint32_t sign_count = be32(auth_data + 33);

    /* UP (user present) must be set */
    if (!(flags & 0x01)) {
        free(att_buf); free(cdj_buf); ERR("UP flag not set"); return -1;
    }
    /* AT (attested credential data) must be set for registration */
    if (!(flags & 0x40)) {
        free(att_buf); free(cdj_buf); ERR("AT flag not set"); return -1;
    }

    const uint8_t *aaguid      = auth_data + 37;
    uint16_t       cred_id_len = be16(auth_data + 53);

    if (auth_data_len < 55u + cred_id_len) {
        free(att_buf); free(cdj_buf); ERR("authData truncated"); return -1;
    }

    const uint8_t *cred_id      = auth_data + 55;
    const uint8_t *cose_key_ptr = auth_data + 55 + cred_id_len;
    size_t         cose_key_len = auth_data_len - 55 - cred_id_len;

    /* --- Decode COSE public key --- */
    uint8_t x[32], y[32];
    int alg = 0;
    if (cbor_parse_cose_key(cose_key_ptr, cose_key_len, x, y, &alg) != 0) {
        free(att_buf); free(cdj_buf); ERR("COSE key parse failed"); return -1;
    }
    if (alg != -7) {
        free(att_buf); free(cdj_buf);
        ERR("unsupported algorithm %d (expected ES256 = -7)", alg); return -1;
    }

    uint8_t pub_der[96];
    size_t  pub_der_len = 0;
    cose_key_to_der(x, y, pub_der, &pub_der_len);

    /* --- Persist user + credential --- */
    int64_t user_id = 0;
    db_user_create(db, username, username, &user_id);
    if (db_cred_store(db, user_id, cred_id, cred_id_len,
                      pub_der, pub_der_len, sign_count, aaguid) != 0) {
        free(att_buf); free(cdj_buf);
        ERR("credential already registered"); return -1;
    }

    free(att_buf);
    free(cdj_buf);
    return 0;
}

/* ---- Authentication: begin ---------------------------------------------- */

typedef struct {
    cJSON  *arr;
} cred_list_ctx_t;

static void cred_list_cb(const uint8_t *cred_id, size_t len, void *ud) {
    cred_list_ctx_t *ctx = (cred_list_ctx_t *)ud;
    char *b64 = b64url_new(cred_id, len);
    if (!b64) return;

    cJSON *item = cJSON_CreateObject();
    cJSON_AddStringToObject(item, "type", "public-key");
    cJSON_AddStringToObject(item, "id",   b64);
    cJSON_AddItemToArray(ctx->arr, item);
    free(b64);
}

cJSON *webauthn_begin_authentication(db_ctx_t *db, const char *username) {
    int64_t user_id = 0;
    if (db_user_find(db, username, &user_id) != 0) return NULL;

    uint8_t challenge[32];
    mg_random(challenge, sizeof(challenge));

    if (db_challenge_store(db, challenge, username, "authentication",
                           (int64_t)time(NULL) + CHAL_TTL) != 0)
        return NULL;

    char *chal_b64 = b64url_new(challenge, sizeof(challenge));
    if (!chal_b64) return NULL;

    cJSON *opts = cJSON_CreateObject();
    cJSON_AddStringToObject(opts, "challenge", chal_b64);
    cJSON_AddNumberToObject(opts, "timeout", 60000);
    cJSON_AddStringToObject(opts, "rpId", RP_ID);
    cJSON_AddStringToObject(opts, "userVerification", "preferred");

    cJSON *allow = cJSON_CreateArray();
    cred_list_ctx_t cl = { .arr = allow };
    db_creds_for_user(db, user_id, cred_list_cb, &cl);
    cJSON_AddItemToObject(opts, "allowCredentials", allow);

    free(chal_b64);
    return opts;
}

/* ---- Authentication: verify --------------------------------------------- */

char *webauthn_verify_authentication(db_ctx_t *db, cJSON *assertion,
                                     char *err_out, size_t err_cap) {
    cJSON *raw_id = cJSON_GetObjectItemCaseSensitive(assertion, "rawId");
    cJSON *resp   = cJSON_GetObjectItemCaseSensitive(assertion, "response");
    if (!cJSON_IsString(raw_id) || !cJSON_IsObject(resp)) {
        ERR("missing rawId or response"); return NULL;
    }

    cJSON *auth_b64 = cJSON_GetObjectItemCaseSensitive(resp, "authenticatorData");
    cJSON *cdj_b64  = cJSON_GetObjectItemCaseSensitive(resp, "clientDataJSON");
    cJSON *sig_b64  = cJSON_GetObjectItemCaseSensitive(resp, "signature");
    if (!cJSON_IsString(auth_b64) || !cJSON_IsString(cdj_b64) || !cJSON_IsString(sig_b64)) {
        ERR("missing response fields"); return NULL;
    }

    /* --- Decode credential ID, look up in DB --- */
    const char *raw_id_str = raw_id->valuestring;
    size_t cred_id_len = strlen(raw_id_str) * 3 / 4 + 4;
    uint8_t *cred_id   = malloc(cred_id_len);
    if (!cred_id) { ERR("oom"); return NULL; }

    if (base64url_decode(raw_id_str, strlen(raw_id_str), cred_id, &cred_id_len) != 0) {
        free(cred_id); ERR("bad rawId b64"); return NULL;
    }

    int64_t  user_id     = 0;
    uint8_t *pub_der     = NULL;
    size_t   pub_der_len = 0;
    uint32_t stored_sc   = 0;

    if (db_cred_find(db, cred_id, cred_id_len,
                     &user_id, &pub_der, &pub_der_len, &stored_sc) != 0) {
        free(cred_id); ERR("credential not found"); return NULL;
    }

    /* --- Decode clientDataJSON --- */
    const char *cdj_str = cdj_b64->valuestring;
    size_t cdj_raw_len  = strlen(cdj_str) * 3 / 4 + 4;
    uint8_t *cdj_raw    = malloc(cdj_raw_len);
    if (!cdj_raw) { free(cred_id); free(pub_der); ERR("oom"); return NULL; }

    if (base64url_decode(cdj_str, strlen(cdj_str), cdj_raw, &cdj_raw_len) != 0) {
        free(cred_id); free(pub_der); free(cdj_raw);
        ERR("bad clientDataJSON b64"); return NULL;
    }

    uint8_t *cdj_buf = realloc(cdj_raw, cdj_raw_len + 1);
    if (!cdj_buf) { free(cdj_raw); free(cred_id); free(pub_der); ERR("oom"); return NULL; }
    cdj_buf[cdj_raw_len] = '\0';

    cJSON *cdj = cJSON_ParseWithLength((char *)cdj_buf, cdj_raw_len);
    if (!cdj) {
        free(cdj_buf); free(cred_id); free(pub_der);
        ERR("clientDataJSON parse failed"); return NULL;
    }

    cJSON *type = cJSON_GetObjectItemCaseSensitive(cdj, "type");
    if (!cJSON_IsString(type) || strcmp(type->valuestring, "webauthn.get") != 0) {
        cJSON_Delete(cdj); free(cdj_buf); free(cred_id); free(pub_der);
        ERR("wrong type"); return NULL;
    }

    cJSON *origin = cJSON_GetObjectItemCaseSensitive(cdj, "origin");
    if (!cJSON_IsString(origin) || strcmp(origin->valuestring, ORIGIN) != 0) {
        cJSON_Delete(cdj); free(cdj_buf); free(cred_id); free(pub_der);
        ERR("origin mismatch"); return NULL;
    }

    cJSON *chal_json = cJSON_GetObjectItemCaseSensitive(cdj, "challenge");
    if (!cJSON_IsString(chal_json)) {
        cJSON_Delete(cdj); free(cdj_buf); free(cred_id); free(pub_der);
        ERR("missing challenge"); return NULL;
    }

    uint8_t chal_bytes[64];
    size_t  chal_len = sizeof(chal_bytes);
    if (base64url_decode(chal_json->valuestring, strlen(chal_json->valuestring),
                         chal_bytes, &chal_len) != 0) {
        cJSON_Delete(cdj); free(cdj_buf); free(cred_id); free(pub_der);
        ERR("bad challenge b64"); return NULL;
    }

    char username[256] = {0};
    if (db_challenge_consume(db, chal_bytes, chal_len, "authentication",
                             username, sizeof(username)) != 0) {
        cJSON_Delete(cdj); free(cdj_buf); free(cred_id); free(pub_der);
        ERR("challenge not found or expired"); return NULL;
    }
    cJSON_Delete(cdj);

    /* --- Decode authenticatorData --- */
    const char *auth_str = auth_b64->valuestring;
    size_t auth_len      = strlen(auth_str) * 3 / 4 + 4;
    uint8_t *auth_buf    = malloc(auth_len);
    if (!auth_buf) { free(cdj_buf); free(cred_id); free(pub_der); ERR("oom"); return NULL; }

    if (base64url_decode(auth_str, strlen(auth_str), auth_buf, &auth_len) != 0) {
        free(auth_buf); free(cdj_buf); free(cred_id); free(pub_der);
        ERR("bad authenticatorData b64"); return NULL;
    }

    if (auth_len < 37) {
        free(auth_buf); free(cdj_buf); free(cred_id); free(pub_der);
        ERR("authData too short"); return NULL;
    }

    /* Verify rpIdHash */
    uint8_t rp_hash[32];
    sha256((const uint8_t *)RP_ID, strlen(RP_ID), rp_hash);
    if (memcmp(auth_buf, rp_hash, 32) != 0) {
        free(auth_buf); free(cdj_buf); free(cred_id); free(pub_der);
        ERR("rpIdHash mismatch"); return NULL;
    }

    uint8_t  flags    = auth_buf[32];
    uint32_t new_sc   = be32(auth_buf + 33);

    if (!(flags & 0x01)) {
        free(auth_buf); free(cdj_buf); free(cred_id); free(pub_der);
        ERR("UP flag not set"); return NULL;
    }

    /* Enforce sign count (skip if authenticator reports 0 — it doesn't track) */
    if (new_sc != 0 && new_sc <= stored_sc) {
        free(auth_buf); free(cdj_buf); free(cred_id); free(pub_der);
        ERR("sign count replay detected"); return NULL;
    }

    /* --- Build verification message: authData || sha256(clientDataJSON) --- */
    uint8_t cdj_hash[32];
    sha256(cdj_buf, cdj_raw_len, cdj_hash);

    size_t   msg_len = auth_len + 32;
    uint8_t *msg     = malloc(msg_len);
    if (!msg) {
        free(auth_buf); free(cdj_buf); free(cred_id); free(pub_der);
        ERR("oom"); return NULL;
    }
    memcpy(msg,           auth_buf,  auth_len);
    memcpy(msg + auth_len, cdj_hash, 32);

    /* --- Decode and verify signature --- */
    const char *sig_str = sig_b64->valuestring;
    size_t sig_len      = strlen(sig_str) * 3 / 4 + 4;
    uint8_t *sig_buf    = malloc(sig_len);
    if (!sig_buf) {
        free(msg); free(auth_buf); free(cdj_buf); free(cred_id); free(pub_der);
        ERR("oom"); return NULL;
    }

    if (base64url_decode(sig_str, strlen(sig_str), sig_buf, &sig_len) != 0) {
        free(sig_buf); free(msg); free(auth_buf); free(cdj_buf); free(cred_id); free(pub_der);
        ERR("bad signature b64"); return NULL;
    }

    int verify_rc = ecdsa_p256_verify(pub_der, pub_der_len,
                                      msg, msg_len, sig_buf, sig_len);
    free(sig_buf);
    free(msg);
    free(auth_buf);
    free(cdj_buf);
    free(pub_der);

    if (verify_rc != 0) {
        free(cred_id);
        ERR("signature verification failed"); return NULL;
    }

    /* Update sign count and return username */
    db_cred_update_sign_count(db, cred_id, cred_id_len, new_sc);
    free(cred_id);

    return strdup(username);
}
