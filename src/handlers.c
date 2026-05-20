#include "handlers.h"
#include "webauthn.h"
#include "cJSON.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define JSON_HDRS "Content-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\n"

/* Send a JSON reply: {"ok": true} or {"ok": false, "error": "..."} */
static void reply_ok(struct mg_connection *c) {
    mg_http_reply(c, 200, JSON_HDRS, "{\"ok\":true}");
}

static void reply_err(struct mg_connection *c, int status, const char *msg) {
    mg_http_reply(c, status, JSON_HDRS, "{\"ok\":false,\"error\":\"%s\"}", msg);
}

/* Parse JSON body from mongoose HTTP message. Returns NULL on failure.
   Caller must cJSON_Delete() the result. */
static cJSON *parse_body(struct mg_http_message *hm) {
    if (hm->body.len == 0) return NULL;
    char *buf = strndup(hm->body.buf, hm->body.len);
    if (!buf) return NULL;
    cJSON *j = cJSON_Parse(buf);
    free(buf);
    return j;
}

/* ---- /api/register/begin ------------------------------------------------ */

static void handle_register_begin(struct mg_connection *c,
                                   struct mg_http_message *hm,
                                   db_ctx_t *db) {
    cJSON *req = parse_body(hm);
    if (!req) { reply_err(c, 400, "bad json"); return; }

    cJSON *uname = cJSON_GetObjectItemCaseSensitive(req, "username");
    if (!cJSON_IsString(uname) || !uname->valuestring[0]) {
        cJSON_Delete(req); reply_err(c, 400, "missing username"); return;
    }

    cJSON *opts = webauthn_begin_registration(db, uname->valuestring);
    cJSON_Delete(req);
    if (!opts) { reply_err(c, 500, "internal error"); return; }

    char *json_str = cJSON_PrintUnformatted(opts);
    cJSON_Delete(opts);
    mg_http_reply(c, 200, JSON_HDRS, "%s", json_str);
    free(json_str);
}

/* ---- /api/register/complete --------------------------------------------- */

static void handle_register_complete(struct mg_connection *c,
                                      struct mg_http_message *hm,
                                      db_ctx_t *db) {
    cJSON *req = parse_body(hm);
    if (!req) { reply_err(c, 400, "bad json"); return; }

    char err[256] = {0};
    int rc = webauthn_verify_registration(db, req, err, sizeof(err));
    cJSON_Delete(req);

    if (rc != 0) reply_err(c, 400, err[0] ? err : "registration failed");
    else         reply_ok(c);
}

/* ---- /api/auth/begin ---------------------------------------------------- */

static void handle_auth_begin(struct mg_connection *c,
                               struct mg_http_message *hm,
                               db_ctx_t *db) {
    cJSON *req = parse_body(hm);
    if (!req) { reply_err(c, 400, "bad json"); return; }

    cJSON *uname = cJSON_GetObjectItemCaseSensitive(req, "username");
    if (!cJSON_IsString(uname) || !uname->valuestring[0]) {
        cJSON_Delete(req); reply_err(c, 400, "missing username"); return;
    }

    cJSON *opts = webauthn_begin_authentication(db, uname->valuestring);
    cJSON_Delete(req);
    if (!opts) { reply_err(c, 404, "user not found or no credentials"); return; }

    char *json_str = cJSON_PrintUnformatted(opts);
    cJSON_Delete(opts);
    mg_http_reply(c, 200, JSON_HDRS, "%s", json_str);
    free(json_str);
}

/* ---- /api/auth/complete ------------------------------------------------- */

static void handle_auth_complete(struct mg_connection *c,
                                  struct mg_http_message *hm,
                                  db_ctx_t *db) {
    cJSON *req = parse_body(hm);
    if (!req) { reply_err(c, 400, "bad json"); return; }

    char err[256] = {0};
    char *username = webauthn_verify_authentication(db, req, err, sizeof(err));
    cJSON_Delete(req);

    if (!username) {
        reply_err(c, 400, err[0] ? err : "authentication failed");
        return;
    }

    /* Generate a simple random session token for demo purposes */
    uint8_t tok_bytes[16];
    mg_random(tok_bytes, sizeof(tok_bytes));
    char token[33];
    for (int i = 0; i < 16; i++)
        snprintf(token + i * 2, 3, "%02x", tok_bytes[i]);

    mg_http_reply(c, 200, JSON_HDRS,
                  "{\"ok\":true,\"username\":\"%s\",\"token\":\"%s\"}",
                  username, token);
    free(username);
}

/* ---- Main event handler ------------------------------------------------- */

void http_event_handler(struct mg_connection *c, int ev, void *ev_data) {
    if (ev != MG_EV_HTTP_MSG) return;

    struct mg_http_message *hm = (struct mg_http_message *)ev_data;
    app_ctx_t *app = (app_ctx_t *)c->fn_data;

    /* CORS preflight */
    if (mg_match(hm->method, mg_str("OPTIONS"), NULL)) {
        mg_http_reply(c, 204,
                      "Access-Control-Allow-Origin: *\r\n"
                      "Access-Control-Allow-Methods: POST, OPTIONS\r\n"
                      "Access-Control-Allow-Headers: Content-Type\r\n",
                      "");
        return;
    }

    if (mg_match(hm->uri, mg_str("/api/register/begin"), NULL)) {
        handle_register_begin(c, hm, app->db);
    } else if (mg_match(hm->uri, mg_str("/api/register/complete"), NULL)) {
        handle_register_complete(c, hm, app->db);
    } else if (mg_match(hm->uri, mg_str("/api/auth/begin"), NULL)) {
        handle_auth_begin(c, hm, app->db);
    } else if (mg_match(hm->uri, mg_str("/api/auth/complete"), NULL)) {
        handle_auth_complete(c, hm, app->db);
    } else {
        struct mg_http_serve_opts opts = { .root_dir = "./frontend" };
        mg_http_serve_dir(c, hm, &opts);
    }
}
