# c-passkey-playground

> **Experimental / learning code.** This is not production-ready. It exists to explore how passkey (WebAuthn) authentication works at the protocol level in pure C.

## What it is

A minimal WebAuthn authentication backend written in C11, backed by SQLite, with a small HTML/JS frontend for testing in the browser. It implements the registration and authentication ceremonies from scratch — CBOR decoding, authData parsing, COSE key extraction, and ECDSA-P256 signature verification — to make the protocol mechanics visible rather than hidden behind a library.

## Dependencies

- **[mongoose](https://github.com/cesanta/mongoose)** — single-file HTTP server and static file serving
- **[SQLite](https://sqlite.org)** — credential and challenge storage (amalgamation, compiled directly)
- **[cJSON](https://github.com/DaveGamble/cJSON)** — JSON parsing and generation
- **OpenSSL 3** — SHA-256 and ECDSA-P256 signature verification

## Build

```sh
# macOS (Homebrew OpenSSL required)
brew install openssl

make vendor-fetch   # download mongoose, cJSON, sqlite3 amalgamation
make
```

## Run

```sh
./passkey-server
# Open http://localhost:8080 in Chrome, Safari, or Firefox
```

Requires a platform authenticator (Touch ID, Face ID, Windows Hello) in the browser.

Options:

```sh
./passkey-server --port 9090 --db mykeys.db
```

## What's implemented

- Registration ceremony: challenge generation, `clientDataJSON` + `attestationObject` verification, authData parsing, COSE key extraction, credential storage
- Authentication ceremony: challenge generation, assertion verification, ECDSA-P256 signature check over `authData || SHA-256(clientDataJSON)`, sign-count enforcement
- Attestation format: `none` (what browsers produce for platform authenticators)
- Algorithm: ES256 (ECDSA-P256)

## What's not implemented

- RS256 / Ed25519
- Attestation verification (packed, TPM, android-key, etc.)
- User verification beyond the UP flag
- Resident keys / discoverable credentials
- Session management beyond a demo token
