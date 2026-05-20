#include "crypto.h"
#include <string.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

/* ---- base64url ---------------------------------------------------------- */

static const char B64URL_CHARS[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

int base64url_encode(const uint8_t *in, size_t in_len, char *out, size_t out_cap) {
    size_t out_len = ((in_len + 2) / 3) * 4;
    if (out_cap < out_len + 1) return -1;

    size_t i = 0, j = 0;
    for (; i + 2 < in_len; i += 3) {
        uint32_t v = ((uint32_t)in[i] << 16) | ((uint32_t)in[i+1] << 8) | in[i+2];
        out[j++] = B64URL_CHARS[(v >> 18) & 0x3f];
        out[j++] = B64URL_CHARS[(v >> 12) & 0x3f];
        out[j++] = B64URL_CHARS[(v >>  6) & 0x3f];
        out[j++] = B64URL_CHARS[(v      ) & 0x3f];
    }
    if (i < in_len) {
        uint32_t v = (uint32_t)in[i] << 16;
        if (i + 1 < in_len) v |= (uint32_t)in[i+1] << 8;
        out[j++] = B64URL_CHARS[(v >> 18) & 0x3f];
        out[j++] = B64URL_CHARS[(v >> 12) & 0x3f];
        if (i + 1 < in_len) out[j++] = B64URL_CHARS[(v >> 6) & 0x3f];
    }
    out[j] = '\0';
    return (int)j;
}

static const int8_t B64URL_TABLE[256] = {
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,  /* '-'=62 */
    52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,  /* '0'-'9'=52-61 */
    -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14, /* 'A'-'O' */
    15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,63,  /* 'P'-'Z', '_'=63 */
    -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40, /* 'a'-'o' */
    41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1, /* 'p'-'z' */
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
};

int base64url_decode(const char *in, size_t in_len, uint8_t *out, size_t *out_len) {
    size_t pos = 0;
    uint32_t accum = 0;
    int bits = 0;

    for (size_t i = 0; i < in_len; i++) {
        char c = in[i];
        if (c == '=') break;
        int8_t v = B64URL_TABLE[(uint8_t)c];
        if (v < 0) return -1;
        accum = (accum << 6) | (uint32_t)v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out[pos++] = (uint8_t)(accum >> bits);
            accum &= (1u << bits) - 1;
        }
    }
    *out_len = pos;
    return 0;
}

/* ---- SHA-256 ------------------------------------------------------------ */

void sha256(const uint8_t *in, size_t in_len, uint8_t out[32]) {
    SHA256(in, in_len, out);
}

/* ---- DER SubjectPublicKeyInfo for P-256 --------------------------------- */

/*
 * Fixed DER prefix for P-256 SubjectPublicKeyInfo (27 bytes):
 *   SEQUENCE { SEQUENCE { OID ecPublicKey, OID prime256v1 } BIT STRING { 04 || x || y } }
 */
static const uint8_t SPKI_PREFIX[27] = {
    0x30, 0x59,                          /* SEQUENCE, 89 bytes */
    0x30, 0x13,                          /* SEQUENCE, 19 bytes */
    0x06, 0x07,                          /* OID, 7 bytes */
    0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,  /* ecPublicKey */
    0x06, 0x08,                          /* OID, 8 bytes */
    0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, /* prime256v1 */
    0x03, 0x42, 0x00,                    /* BIT STRING, 66 bytes, 0 unused bits */
    0x04                                 /* uncompressed point marker */
};

#define SPKI_LEN (sizeof(SPKI_PREFIX) + 32 + 32)  /* 91 */

int cose_key_to_der(const uint8_t x[32], const uint8_t y[32],
                    uint8_t *out_der, size_t *out_len) {
    memcpy(out_der, SPKI_PREFIX, sizeof(SPKI_PREFIX));
    memcpy(out_der + sizeof(SPKI_PREFIX),      x, 32);
    memcpy(out_der + sizeof(SPKI_PREFIX) + 32, y, 32);
    *out_len = SPKI_LEN;
    return 0;
}

/* ---- ECDSA-P256/SHA-256 verification ------------------------------------ */

int ecdsa_p256_verify(const uint8_t *pub_key_der, size_t der_len,
                      const uint8_t *msg,         size_t msg_len,
                      const uint8_t *sig_der,     size_t sig_len) {
    const uint8_t *p = pub_key_der;
    EVP_PKEY *pkey = d2i_PUBKEY_ex(NULL, &p, (long)der_len, NULL, NULL);
    if (!pkey) return -1;

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) { EVP_PKEY_free(pkey); return -1; }

    int rc = EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, pkey);
    if (rc != 1) goto fail;

    rc = EVP_DigestVerifyUpdate(ctx, msg, msg_len);
    if (rc != 1) goto fail;

    rc = EVP_DigestVerifyFinal(ctx, sig_der, sig_len);

fail:
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return (rc == 1) ? 0 : -1;
}
