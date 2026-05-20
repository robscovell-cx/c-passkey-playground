#pragma once
#include <stdint.h>
#include <stddef.h>

/* base64url (RFC 4648 §5) — no padding, URL-safe alphabet */
int  base64url_encode(const uint8_t *in, size_t in_len, char *out, size_t out_cap);
int  base64url_decode(const char *in, size_t in_len, uint8_t *out, size_t *out_len);

/* SHA-256 */
void sha256(const uint8_t *in, size_t in_len, uint8_t out[32]);

/* Build a 91-byte DER SubjectPublicKeyInfo for an uncompressed P-256 point */
int  cose_key_to_der(const uint8_t x[32], const uint8_t y[32],
                     uint8_t *out_der, size_t *out_len);

/* Verify an ECDSA-P256/SHA-256 signature.
   pub_key_der: DER SubjectPublicKeyInfo (91 bytes from cose_key_to_der).
   msg:         raw message bytes (authData || sha256(clientDataJSON)).
   sig_der:     DER-encoded ECDSA signature from the browser.
   Returns 0 on success, -1 on failure. */
int  ecdsa_p256_verify(const uint8_t *pub_key_der, size_t der_len,
                       const uint8_t *msg,         size_t msg_len,
                       const uint8_t *sig_der,     size_t sig_len);
