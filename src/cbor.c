#include "cbor.h"
#include <string.h>

int cbor_decode_one(const uint8_t *buf, size_t len, cbor_value_t *out) {
    if (len == 0) return -1;

    uint8_t  initial = buf[0];
    uint8_t  major   = initial >> 5;
    uint8_t  addl    = initial & 0x1f;
    size_t   hdr     = 1;
    uint64_t val     = 0;

    if (addl <= 23) {
        val = addl;
    } else if (addl == 24) {
        if (len < 2) return -1;
        val = buf[1];
        hdr = 2;
    } else if (addl == 25) {
        if (len < 3) return -1;
        val = ((uint64_t)buf[1] << 8) | buf[2];
        hdr = 3;
    } else if (addl == 26) {
        if (len < 5) return -1;
        val = ((uint64_t)buf[1] << 24) | ((uint64_t)buf[2] << 16)
            | ((uint64_t)buf[3] <<  8) |  (uint64_t)buf[4];
        hdr = 5;
    } else {
        return -1;  /* 64-bit args and indefinite lengths not supported */
    }

    out->type = (cbor_type_t)major;

    switch (major) {
        case 0:  /* unsigned int */
            out->uint = val;
            return (int)hdr;

        case 1:  /* negative int: actual value = -1 - val */
            out->negint = -1 - (int64_t)val;
            return (int)hdr;

        case 2:  /* byte string */
            if (hdr + val > len) return -1;
            out->bytes.ptr = buf + hdr;
            out->bytes.len = (size_t)val;
            return (int)(hdr + val);

        case 3:  /* text string */
            if (hdr + val > len) return -1;
            out->text.ptr = (const char *)(buf + hdr);
            out->text.len = (size_t)val;
            return (int)(hdr + val);

        case 4:  /* array */
            out->array_len = val;
            return (int)hdr;

        case 5:  /* map */
            out->map_len = val;
            return (int)hdr;

        default:
            out->type = CBOR_INVALID;
            return -1;
    }
}

int cbor_skip(const uint8_t *buf, size_t len) {
    cbor_value_t v;
    int consumed = cbor_decode_one(buf, len, &v);
    if (consumed < 0) return -1;

    size_t off = (size_t)consumed;

    if (v.type == CBOR_MAP) {
        for (uint64_t i = 0; i < v.map_len * 2; i++) {
            int n = cbor_skip(buf + off, len - off);
            if (n < 0) return -1;
            off += (size_t)n;
        }
        return (int)off;
    }

    if (v.type == CBOR_ARRAY) {
        for (uint64_t i = 0; i < v.array_len; i++) {
            int n = cbor_skip(buf + off, len - off);
            if (n < 0) return -1;
            off += (size_t)n;
        }
        return (int)off;
    }

    /* BYTES and TEXT: payload already consumed by cbor_decode_one */
    /* UINT, NEGINT: no payload beyond the header */
    return (int)off;
}

int cbor_parse_attestation_object(const uint8_t *buf, size_t len,
                                  const uint8_t **auth_data, size_t *auth_data_len,
                                  char *fmt_out, size_t fmt_cap) {
    cbor_value_t map_hdr;
    int hdr_sz = cbor_decode_one(buf, len, &map_hdr);
    if (hdr_sz < 0 || map_hdr.type != CBOR_MAP) return -1;

    *auth_data      = NULL;
    *auth_data_len  = 0;
    if (fmt_cap > 0) fmt_out[0] = '\0';

    size_t off = (size_t)hdr_sz;

    for (uint64_t i = 0; i < map_hdr.map_len; i++) {
        cbor_value_t key;
        int ksz = cbor_decode_one(buf + off, len - off, &key);
        if (ksz < 0) return -1;
        off += (size_t)ksz;

        if (key.type == CBOR_TEXT) {
            size_t klen = key.text.len;

            if (klen == 3 && memcmp(key.text.ptr, "fmt", 3) == 0) {
                cbor_value_t val;
                int vsz = cbor_decode_one(buf + off, len - off, &val);
                if (vsz < 0) return -1;
                if (val.type == CBOR_TEXT && fmt_cap > 0) {
                    size_t copy = val.text.len < fmt_cap - 1
                                  ? val.text.len : fmt_cap - 1;
                    memcpy(fmt_out, val.text.ptr, copy);
                    fmt_out[copy] = '\0';
                }
                off += (size_t)vsz;
                continue;
            }

            if (klen == 8 && memcmp(key.text.ptr, "authData", 8) == 0) {
                cbor_value_t val;
                int vsz = cbor_decode_one(buf + off, len - off, &val);
                if (vsz < 0) return -1;
                if (val.type == CBOR_BYTES) {
                    *auth_data     = val.bytes.ptr;
                    *auth_data_len = val.bytes.len;
                }
                off += (size_t)vsz;
                continue;
            }
        }

        /* Unknown key — skip the value */
        int vsz = cbor_skip(buf + off, len - off);
        if (vsz < 0) return -1;
        off += (size_t)vsz;
    }

    return (*auth_data != NULL) ? 0 : -1;
}

int cbor_parse_cose_key(const uint8_t *buf, size_t len,
                        uint8_t x[32], uint8_t y[32], int *alg_out) {
    cbor_value_t map_hdr;
    int hdr_sz = cbor_decode_one(buf, len, &map_hdr);
    if (hdr_sz < 0 || map_hdr.type != CBOR_MAP) return -1;

    size_t off   = (size_t)hdr_sz;
    int    got_x = 0, got_y = 0;
    *alg_out = 0;

    for (uint64_t i = 0; i < map_hdr.map_len; i++) {
        cbor_value_t key;
        int ksz = cbor_decode_one(buf + off, len - off, &key);
        if (ksz < 0) return -1;
        off += (size_t)ksz;

        cbor_value_t val;
        int vsz = cbor_decode_one(buf + off, len - off, &val);
        if (vsz < 0) return -1;

        if (key.type == CBOR_UINT || key.type == CBOR_NEGINT) {
            int64_t k = (key.type == CBOR_UINT)
                        ? (int64_t)key.uint : key.negint;

            if (k == 3) {
                /* alg: -7 = ES256 */
                if (val.type == CBOR_NEGINT) *alg_out = (int)val.negint;
                else if (val.type == CBOR_UINT) *alg_out = (int)val.uint;
            } else if (k == -2 && val.type == CBOR_BYTES && val.bytes.len == 32) {
                memcpy(x, val.bytes.ptr, 32);
                got_x = 1;
            } else if (k == -3 && val.type == CBOR_BYTES && val.bytes.len == 32) {
                memcpy(y, val.bytes.ptr, 32);
                got_y = 1;
            }
        }
        off += (size_t)vsz;
    }

    return (got_x && got_y) ? 0 : -1;
}
