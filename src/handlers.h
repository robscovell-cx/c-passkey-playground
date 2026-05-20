#pragma once
#include "db.h"
#include "mongoose.h"

typedef struct {
    db_ctx_t *db;
} app_ctx_t;

void http_event_handler(struct mg_connection *c, int ev, void *ev_data);
