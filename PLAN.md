# C Passkey Authentication Backend — Project Reference

## Overview

A passkey (WebAuthn/FIDO2) authentication backend in pure C with SQLite for persistence
and a minimal HTML/JS frontend for browser testing. Implements full registration and
authentication ceremonies including discoverable credentials (Conditional UI).

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

## Build

```bash
make vendor-fetch   # download mongoose, cJSON, sqlite3 amalgamation
make                # build passkey-server; .o files cleaned up automatically after linking
./passkey-server    # serves on http://localhost:8080
```

**Compiler**: clang, `-std=c99 -Wall -Wextra`
**Dependencies**: OpenSSL 3 (`brew install openssl@3`), vendored mongoose/cJSON/sqlite3

## Dependencies

| Library             | Purpose                           | How          |
|---------------------|-----------------------------------|--------------|
| mongoose 7.x        | HTTP server + static file serving | Vendored     |
| cJSON               | JSON parse/generate               | Vendored     |
| SQLite amalgamation | Persistence                       | Vendored     |
| OpenSSL 3           | SHA-256, ECDSA-P256 verify        | System (brew)|

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
  username TEXT NOT NULL,         -- empty string "" for discoverable flow
  type TEXT NOT NULL,             -- 'registration' or 'authentication'
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL     -- time(NULL) + 300
);
```

## API Endpoints

| Method  | Path                   | Description                                   |
|---------|------------------------|-----------------------------------------------|
| POST    | /api/register/begin    | Returns WebAuthn creation options             |
| POST    | /api/register/complete | Verifies attestation, stores credential       |
| POST    | /api/auth/begin        | Returns assertion options (username optional) |
| POST    | /api/auth/complete     | Verifies assertion, returns username + token  |
| OPTIONS | *                      | 204 with CORS headers (browser preflight)     |
| GET/etc | (all others)           | Serves ./frontend/ static files               |

`/api/auth/begin` accepts `{}` (no username) for the discoverable flow — returns empty
`allowCredentials` so the browser discovers stored passkeys itself.

## Authentication Flows

Three paths coexist:

1. **Named flow** (username typed): POST `{username}` → `allowCredentials` populated →
   browser shows only matching passkeys.

2. **Discoverable modal** (button, no username): POST `{}` → `allowCredentials:[]` →
   browser shows all stored passkeys for the RP.

3. **Conditional UI / autofill**: `initConditionalUI()` arms a passive `get()` on page
   load with `mediation:"conditional"`. The browser surfaces passkeys in the username
   autofill dropdown without any user gesture. Cancelled via `AbortController` when the
   button flow starts.

## Key Implementation Details

### C99 Compatibility

The CBOR value union is named (`.u`) for C99 — anonymous unions are C11-only:

```c
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
```

Access: `v.u.uint`, `v.u.bytes.ptr`, `v.u.map_len`, etc.

### Discoverable Credentials (`src/db.h`, `src/webauthn.c`, `src/handlers.c`)

- `db_user_find_by_id(ctx, user_id, out_username, cap)` — reverse lookup by user_id
- `webauthn_begin_authentication(db, NULL)` — stores `""` as challenge username, returns
  empty `allowCredentials` array
- `webauthn_verify_authentication` — if `username[0]=='\0'` after consuming challenge,
  resolves username via `db_user_find_by_id(db, user_id, ...)`

### WebAuthn Registration (`webauthn_verify_registration`)

1. Decode + parse clientDataJSON; verify `type=="webauthn.create"`, `origin==ORIGIN`
2. Decode challenge from clientDataJSON; `db_challenge_consume` (atomic find+delete)
3. Decode attestationObject (CBOR); `cbor_parse_attestation_object` → authData bytes
4. Parse authData binary layout:
   - `[0..31]`  rpIdHash — verify `== sha256("localhost")`
   - `[32]`     flags — UP (0x01) and AT (0x40) must be set
   - `[33..36]` signCount (big-endian uint32)
   - `[37..52]` AAGUID (16 bytes)
   - `[53..54]` credentialIdLength (big-endian uint16)
   - `[55..]`   credentialId, then credentialPublicKey (CBOR COSE_Key)
5. `cbor_parse_cose_key` → x[32], y[32]; verify `alg == -7` (ES256)
6. `cose_key_to_der` — prepend 27-byte SPKI_PREFIX to x+y → 91-byte DER
7. `db_user_create` (idempotent upsert); `db_cred_store`

### ECDSA-P256 Key Format (`src/crypto.c`)

91-byte SubjectPublicKeyInfo DER built by prepending a hardcoded 27-byte prefix:

```c
static const uint8_t SPKI_PREFIX[27] = {
    0x30,0x59, 0x30,0x13,
    0x06,0x07, 0x2a,0x86,0x48,0xce,0x3d,0x02,0x01,       // ecPublicKey OID
    0x06,0x08, 0x2a,0x86,0x48,0xce,0x3d,0x03,0x01,0x07,  // prime256v1 OID
    0x03,0x42,0x00, 0x04                                   // BIT STRING + uncompressed point
};
```

Verification uses OpenSSL 3 EVP high-level API (no deprecated EC_KEY functions):
`d2i_PUBKEY_ex` → `EVP_DigestVerifyInit/Update/Final`

## Key Traps

1. **Big-endian in authData**: `signCount` (offset 33, uint32) and `credentialIdLength`
   (offset 53, uint16) are big-endian. Use `be32`/`be16` helpers.
2. **base64url ≠ base64**: Mongoose decodes standard base64 only. Custom table-driven
   decoder handles `-`→62, `_`→63, no padding required.
3. **"none" attestation**: `attStmt` is an empty CBOR map — no signature to verify.
4. **COSE negative int labels**: CBOR encodes -2 as major type 1, argument 1.
5. **challenge in clientDataJSON**: browser base64url-encodes it — decode before
   comparing to DB value.
6. **`db_cred_find` allocates**: caller must `free(pub_key_der)` after use.
7. **`hm->body.buf` is NOT null-terminated**: always `strndup(hm->body.buf, hm->body.len)`
   before `cJSON_Parse`.

## Verification

```bash
make && ./passkey-server
# Open http://localhost:8080 in Chrome/Safari
# Register → browser Touch ID/Face ID/Windows Hello prompt → "Passkey registered!"
# Login (named)      → type username, click Login → passkey prompt → "Logged in as alice!"
# Login (discoverable) → leave username blank, click Login → browser modal
# Login (conditional UI) → click username field → browser autofill dropdown
sqlite3 passkeys.db \
  "SELECT u.username, hex(c.credential_id) \
   FROM credentials c JOIN users u ON u.id = c.user_id;"
```
