# Plan: C Passkey Authentication Backend

## Context

Build a passkey (WebAuthn/FIDO2) authentication backend in pure C with SQLite for persistence and a minimal HTML/JS frontend for browser testing. The repo is currently empty. The goal is a working, spec-compliant WebAuthn implementation that lets users register and authenticate with platform passkeys (Touch ID, Face ID, Windows Hello, etc.) against a localhost server.

---

## Project Structure

```
c-passkey-playground/
├── Makefile
├── .gitignore
├── src/
│   ├── main.c          # Entry point, mongoose event loop
│   ├── handlers.c/h    # HTTP routing and JSON I/O
│   ├── webauthn.c/h    # Registration + authentication ceremonies
│   ├── db.c/h          # SQLite CRUD
│   ├── crypto.c/h      # base64url, SHA-256, ECDSA verify, DER key builder
│   └── cbor.c/h        # Minimal CBOR decoder for attestationObject + COSE_Key
├── vendor/
│   ├── mongoose.c + .h  (fetched via make vendor-fetch)
│   ├── cJSON.c + .h
│   └── sqlite3.c + .h   (amalgamation — compiled as separate TU)
└── frontend/
    ├── index.html
    └── app.js
```

---

## Dependencies

| Library | Purpose | How |
|---------|---------|-----|
| mongoose 7.x | HTTP server + static file serving | Vendored single-file |
| cJSON | JSON parse/generate | Vendored single-file |
| SQLite amalgamation | Persistence | Vendored, compiled directly |
| OpenSSL 3 (libssl/libcrypto) | SHA-256, ECDSA-P256 verify | System (`brew install openssl`) |

---

## Database Schema

```sql
CREATE TABLE users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  display_name TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE TABLE credentials (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  credential_id BLOB UNIQUE NOT NULL,
  user_id INTEGER NOT NULL REFERENCES users(id),
  public_key_der BLOB NOT NULL,   -- SubjectPublicKeyInfo DER, 91 bytes for P-256
  sign_count INTEGER NOT NULL DEFAULT 0,
  aaguid BLOB,
  created_at INTEGER NOT NULL
);
CREATE TABLE challenges (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  challenge BLOB NOT NULL,
  username TEXT NOT NULL,
  type TEXT NOT NULL,             -- 'registration' or 'authentication'
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL     -- time(NULL) + 300
);
```

---

## Implementation Plan (ordered by dependency)

### 1. Makefile

- `CFLAGS`: `-std=c11 -Wall -Wextra -Ivendor -Isrc -I/opt/homebrew/opt/openssl@3/include`
- `LDFLAGS`: `-L/opt/homebrew/opt/openssl@3/lib -lssl -lcrypto`
- Compile `vendor/sqlite3.c` separately with `-DSQLITE_THREADSAFE=0 -O2`
- `vendor-fetch` target: curl mongoose, cJSON, sqlite3 amalgamation
- `all`, `clean` targets

### 2. src/crypto.c — No dependencies on other src files

**base64url_decode**: Table-driven; `-` → 62, `_` → 63; stop at `=` or end. Handles unpadded input. Cannot use mongoose's `mg_base64_decode` (standard base64 only).

**base64url_encode**: URL-safe alphabet, no padding (`=`).

**sha256**: `SHA256(in, in_len, out)` via `#include <openssl/sha.h>`.

**cose_key_to_der**: Builds 91-byte DER `SubjectPublicKeyInfo` for P-256 by prepending a hardcoded 27-byte prefix to the 32-byte x then 32-byte y coordinates:
```c
static const uint8_t SPKI_PREFIX[27] = {
    0x30,0x59, 0x30,0x13,
    0x06,0x07, 0x2a,0x86,0x48,0xce,0x3d,0x02,0x01,  // ecPublicKey OID
    0x06,0x08, 0x2a,0x86,0x48,0xce,0x3d,0x03,0x01,0x07, // prime256v1 OID
    0x03,0x42,0x00, 0x04  // BIT STRING + uncompressed point marker
};
```

**ecdsa_p256_verify**: OpenSSL EVP high-level API (no deprecation warnings on OpenSSL 3):
```c
EVP_PKEY *pkey = d2i_PUBKEY_ex(NULL, &p, der_len, NULL, NULL);
EVP_MD_CTX *ctx = EVP_MD_CTX_new();
EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, pkey);
EVP_DigestVerifyUpdate(ctx, msg, msg_len);
rc = EVP_DigestVerifyFinal(ctx, sig_der, sig_len);  // 1 = valid
```

Big-endian helpers (authData fields are big-endian on little-endian Apple Silicon):
```c
static uint32_t be32(const uint8_t *p);
static uint16_t be16(const uint8_t *p);
```

### 3. src/cbor.c — No dependencies on other src files

Minimal recursive decoder for: unsigned int (major 0), negative int (major 1), byte string (major 2), text string (major 3), map (major 5). Additional info ≤ 23, 24, 25, 26 (no 64-bit args or indefinite lengths needed).

Key types:
```c
typedef enum { CBOR_UINT, CBOR_NEGINT, CBOR_BYTES, CBOR_TEXT, CBOR_MAP } cbor_type_t;
typedef struct cbor_value { cbor_type_t type; union { ... }; } cbor_value_t;
int cbor_decode_one(const uint8_t *buf, size_t len, cbor_value_t *out); // returns bytes consumed
int cbor_skip(const uint8_t *buf, size_t len);  // skip one complete item (recursive for maps)
int cbor_parse_attestation_object(buf, len, &auth_data_ptr, &auth_data_len, fmt_out);
int cbor_parse_cose_key(buf, len, x[32], y[32], *alg);  // extracts COSE labels -2,-3
```

COSE key labels: integer key `-2` → x (32 bytes), `-3` → y (32 bytes), `3` → alg (-7 = ES256). CBOR encodes `-2` as major type 1, argument 1 (since `-1 - 1 = -2`).

### 4. src/db.c

All queries use `sqlite3_prepare_v2` + `sqlite3_bind_*` + `sqlite3_step` + `sqlite3_finalize`. Never `sqlite3_exec` with user data.

Key functions: `db_init`, `db_close`, `db_user_create` (upsert-safe), `db_user_find`, `db_cred_store`, `db_cred_find` (returns heap-allocated `pub_key_der` — caller must `free()`), `db_cred_update_sign_count`, `db_creds_for_user` (callback-based iterator), `db_challenge_store`, `db_challenge_consume` (atomic find+delete, checks expiry).

### 5. src/webauthn.c

Config constants at top of file:
```c
#define RP_ID   "localhost"
#define RP_NAME "C Passkey Demo"
#define ORIGIN  "http://localhost:8080"
#define CHAL_TTL 300
```

**webauthn_begin_registration(db, username)**:
1. Generate 32 random bytes via `mg_random(challenge, 32)`
2. `db_challenge_store(db, challenge, username, "registration", time(NULL)+CHAL_TTL)`
3. Return cJSON options: `{challenge, rp:{id,name}, user:{id,name,displayName}, pubKeyCredParams:[{type,alg:-7}], timeout:60000, attestation:"none"}`

**webauthn_verify_registration(db, credential_json, err_out)**:
1. base64url-decode `response.clientDataJSON`; parse JSON; verify `type=="webauthn.create"`, `origin==ORIGIN`
2. base64url-decode `challenge` from clientDataJSON; `db_challenge_consume(..., "registration")`
3. `sha256(raw_cdj, len, client_data_hash)` (not needed for "none" attestation but computed for completeness)
4. base64url-decode `response.attestationObject`; `cbor_parse_attestation_object` → `auth_data` bytes
5. Parse authData binary layout:
   - `[0..31]` = rpIdHash; verify == `sha256("localhost")`
   - `[32]` = flags; verify `flags & 0x01` (UP) is set; verify `flags & 0x40` (AT) for attested cred data
   - `[33..36]` = signCount (be32)
   - `[37..52]` = AAGUID (16 bytes)
   - `[53..54]` = credentialIdLength (be16)
   - `[55..55+credIdLen-1]` = credentialId
   - `[55+credIdLen..]` = credentialPublicKey (CBOR)
6. `cbor_parse_cose_key` → x, y; verify `alg == -7`
7. `cose_key_to_der(x, y, pub_key_der, &der_len)`
8. `db_user_create` (idempotent); `db_cred_store`

**webauthn_begin_authentication(db, username)**:
1. `db_user_find` to get user_id; `db_creds_for_user` to collect credential IDs
2. Generate challenge; `db_challenge_store(..., "authentication")`
3. Return cJSON options: `{challenge, allowCredentials:[{type:"public-key", id:base64url(cred_id)},...], timeout:60000, userVerification:"preferred"}`

**webauthn_verify_authentication(db, assertion_json, err_out)** → returns username or NULL:
1. base64url-decode `rawId` → cred_id; `db_cred_find` → pub_key_der, stored_sign_count
2. base64url-decode + parse clientDataJSON; verify `type=="webauthn.get"`, `origin`
3. `db_challenge_consume(..., "authentication")` → username
4. base64url-decode `response.authenticatorData`; parse header; verify rpIdHash, UP flag
5. `new_sign_count = be32(auth_data+33)`; if `new_sign_count > 0`: verify `> stored_sign_count`
6. `message = auth_data || sha256(raw_clientDataJSON)`
7. base64url-decode `response.signature`; `ecdsa_p256_verify(pub_key_der, ..., message, ..., sig, ...)`
8. `db_cred_update_sign_count`; `free(pub_key_der)`; return username

### 6. src/handlers.c

Mongoose event handler dispatches on `hm->uri`:
- `POST /api/register/begin` → `handle_register_begin`
- `POST /api/register/complete` → `handle_register_complete`
- `POST /api/auth/begin` → `handle_auth_begin`
- `POST /api/auth/complete` → `handle_auth_complete`
- `OPTIONS *` → 204 with CORS headers (browser preflight)
- Everything else → `mg_http_serve_dir(c, hm, &(struct mg_http_serve_opts){.root_dir="./frontend"})`

All API responses include `Content-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\n`.

**Important**: `hm->body.buf` is NOT null-terminated — always `strndup(hm->body.buf, hm->body.len)` before `cJSON_Parse`.

`app_ctx_t` holds the `db_ctx_t*` and is passed via `mg_http_listen`'s `fn_data` → `c->fn_data`.

### 7. src/main.c

Parse `--port` and `--db` argv args; `db_init`; `mg_mgr_init`; `mg_http_listen(..., http_event_handler, &app)`; `for(;;) mg_mgr_poll(&mgr, 1000)`.

### 8. frontend/index.html + app.js

Two sections: Register and Login. No framework dependencies. Script loaded as `type="module"` (strict mode + module scope, no global pollution).

Key JS helpers:
```js
function bufferToBase64url(buf) { /* Uint8Array → btoa → replace +/ with -_ → strip = */ }
function base64urlToBuffer(b64) { /* replace -_ → +/ → pad → atob → Uint8Array → ArrayBuffer */ }
async function apiPost(endpoint, payload) { /* shared fetch helper — checks resp.ok before .json() */ }
function checkSupport(statusId) { /* guards on window.PublicKeyCredential before each flow */ }
```

Registration flow: `checkSupport` → `apiPost('/api/register/begin')` → transform `challenge` and `user.id` to `ArrayBuffer` → `navigator.credentials.create({publicKey: options})` → serialize buffers to base64url (including `getTransports()`) → `apiPost('/api/register/complete')`.

Authentication flow: `checkSupport` → `apiPost('/api/auth/begin')` → transform `challenge` and `allowCredentials[].id` to `ArrayBuffer` → `navigator.credentials.get({publicKey: options})` → serialize → `apiPost('/api/auth/complete')`.

---

## Key Traps

1. **Big-endian in authData**: `signCount` (offset 33, uint32) and `credentialIdLength` (offset 53, uint16) are big-endian. Use `be32`/`be16` helpers.
2. **base64url ≠ base64**: Mongoose's decoder handles standard base64 only. Must write our own (table with `-`→62, `_`→63, no padding required).
3. **"none" attestation**: `attStmt` is an empty CBOR map `{}` — no signature to verify. This is what browsers produce; just parse authData.
4. **COSE negative int labels**: CBOR major type 1 encodes -2 as argument=1, -3 as argument=2. The `negint` field stores the mathematical value directly.
5. **OpenSSL 3 API**: Use EVP high-level API (`d2i_PUBKEY_ex`, `EVP_DigestVerify*`) — no deprecated EC_KEY functions.
6. **challenge in clientDataJSON**: The browser base64url-encodes the challenge when embedding it in clientDataJSON. Decode before comparing to DB value.
7. **`db_cred_find` allocates**: Caller must `free(pub_key_der)` after use.

---

## QA Findings (applied)

Issues identified during review of `frontend/app.js` and resolved:

1. **WebAuthn feature detection** — added `checkSupport()` guard checking `window.PublicKeyCredential` at the start of each button handler; fails gracefully with a readable message on unsupported browsers or non-secure contexts.
2. **Fragile JSON parsing on complete steps** — both complete steps now go through `apiPost()` which checks `resp.ok` before calling `.json()`, so a non-JSON 500 response no longer throws an opaque parse error.
3. **Authenticator transports** — registration payload now includes `transports: cred.response.getTransports ? cred.response.getTransports() : []`, which is required by strict server libraries and improves future credential lookup.
4. **Repetitive fetch boilerplate** — extracted shared `apiPost(endpoint, payload)` helper used by all four API calls.
5. **Global scope pollution** — script tag changed to `type="module"`; all functions are now module-scoped.

6. **Discoverable credentials backend** — `db_user_find_by_id()` added; `webauthn_begin_authentication()` now accepts NULL username (stores `""` challenge, returns empty `allowCredentials`); `webauthn_verify_authentication()` resolves username from credential when challenge carries no username; `handle_auth_begin()` makes username field optional.

Frontend-side conditional UI (`mediation: "conditional"` on `navigator.credentials.get()`, optional username input) remains as future work.

---

## Verification

1. `make vendor-fetch && make` — should compile cleanly with no warnings
2. `./passkey-server` — server starts on port 8080
3. Open `http://localhost:8080` in Chrome/Safari/Firefox
4. Register with a username → browser prompts for Touch ID/Face ID/Windows Hello → status shows "Registered!"
5. Login with the same username → browser prompts for passkey → status shows "Logged in! Token: ..."
6. Attempt login with wrong username → error returned
7. Check `passkeys.db` with `sqlite3 passkeys.db "SELECT * FROM credentials;"` to confirm credential stored
