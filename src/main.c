#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "mongoose.h"
#include "handlers.h"
#include "db.h"

int main(int argc, char **argv) {
    const char *port    = "8080";
    const char *db_path = "passkeys.db";

    for (int i = 1; i + 1 < argc; i++) {
        if (strcmp(argv[i], "--port") == 0) port    = argv[i + 1];
        if (strcmp(argv[i], "--db")   == 0) db_path = argv[i + 1];
    }

    db_ctx_t db;
    if (db_init(&db, db_path) != 0) {
        fprintf(stderr, "Failed to open database: %s\n", db_path);
        return 1;
    }

    app_ctx_t app = { .db = &db };

    struct mg_mgr mgr;
    mg_mgr_init(&mgr);

    char url[64];
    snprintf(url, sizeof(url), "http://0.0.0.0:%s", port);

    struct mg_connection *conn =
        mg_http_listen(&mgr, url, http_event_handler, &app);
    if (!conn) {
        fprintf(stderr, "Failed to listen on %s\n", url);
        db_close(&db);
        return 1;
    }

    printf("Passkey server listening on http://localhost:%s\n", port);
    printf("Open your browser to: http://localhost:%s\n", port);

    for (;;) {
        mg_mgr_poll(&mgr, 1000);
    }

    mg_mgr_free(&mgr);
    db_close(&db);
    return 0;
}
