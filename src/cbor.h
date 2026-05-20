#pragma once
#include <stdint.h>
#include <stddef.h>

typedef enum {
    CBOR_UINT    = 0,
    CBOR_NEGINT  = 1,
    CBOR_BYTES   = 2,
    CBOR_TEXT    = 3,
    CBOR_ARRAY   = 4,
    CBOR_MAP     = 5,
    CBOR_INVALID = -1,
} cbor_type_t;

typedef struct {
    cbor_type_t type;
    union {
        uint64_t uint;
        int64_t  negint;
        struct { const uint8_t *ptr; size_t len; } bytes;
        struct { const char    *ptr; size_t len; } text;
        uint64_t map_len;
        uint64_t array_len;
    } u;
} cbor_value_t;

/* Decode one CBOR item header. Returns bytes consumed (>0), or -1 on error.
   For BYTES/TEXT the payload is included in the count. For MAP/ARRAY only
   the header is consumed; the caller iterates the pairs manually. */
int cbor_decode_one(const uint8_t *buf, size_t len, cbor_value_t *out);

/* Skip one complete CBOR item (including any nested payload). */
int cbor_skip(const uint8_t *buf, size_t len);

/* Parse the WebAuthn attestationObject CBOR map.
   Fills *auth_data / *auth_data_len with a pointer into buf (not a copy).
   fmt_out receives the "fmt" text string (NUL-terminated, capped at fmt_cap).
   Returns 0 on success, -1 on error. */
int cbor_parse_attestation_object(const uint8_t *buf, size_t len,
                                  const uint8_t **auth_data, size_t *auth_data_len,
                                  char *fmt_out, size_t fmt_cap);

/* Parse a COSE_Key map (ES256) and extract x[32], y[32].
   *alg_out receives the algorithm integer (-7 for ES256).
   Returns 0 on success, -1 on error. */
int cbor_parse_cose_key(const uint8_t *buf, size_t len,
                        uint8_t x[32], uint8_t y[32], int *alg_out);
