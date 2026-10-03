# API reference

Base URL: `http://127.0.0.1:8000/api/v1`. Interactive OpenAPI: `http://127.0.0.1:8000/docs`. Ordinary JSON requests use `Content-Type: application/json`; authenticated requests use `Authorization: Bearer <opaque-token>`.

Identifiers are UUID strings. Responses include `X-Request-ID`; errors contain that ID in JSON. UUID/timestamp/base64/hash formats and canonical signed bytes are defined in [CRYPTOGRAPHY.md](CRYPTOGRAPHY.md). Unknown schema fields are rejected.

## Authentication and identity

| Method | Path | Request | Result |
|---|---|---|---|
| POST | `/auth/register` | `username`, `password`, `public_key_pem` | 201 public user record |
| POST | `/auth/login` | `username`, `password` | `access_token`, `token_type`, `expires_at`, `user` |
| POST | `/auth/challenge` | `username` | `id`, canonical `metadata` to sign |
| POST | `/auth/challenge/verify` | `challenge_id`, base64 `signature` | Authentication token and user |
| GET | `/auth/me` | Bearer token | Own public user record |
| POST | `/auth/logout` | Bearer token | 204, token revoked |
| GET | `/users` | Bearer token | Active user directory with public keys/fingerprints |
| GET | `/users/{id}/public-key` | Bearer token | Public key, SHA-256 DER fingerprint, username |

Username: 3–32 characters, starts with a letter, subsequent letters/digits/underscore/hyphen; normalized to lowercase. Registration password: 10–128 characters. RSA key: SubjectPublicKeyInfo PEM, 2048–4096 bits, exponent 65537. Private-key fields are never part of a server schema.

Challenge verification signs the **whole returned metadata object**, not just the random challenge string. RSA-PSS uses a 32-byte salt. A challenge is one-use, even after an invalid verification attempt. Account and source-IP throttling apply.

## Transfer creation and discovery

| Method | Path | Request/authorization | Result |
|---|---|---|---|
| POST | `/transfers` | Sender bearer token, UUID `Idempotency-Key`, JSON below | 201 transfer; same result for repeated identical key/payload |
| GET | `/transfers/sent` | Sender's identity | Latest 200 sent transfers |
| GET | `/transfers/received` | Receiver's identity | Latest 200 incoming transfers |
| GET | `/transfers/stats` | Authenticated participant | Aggregate sent/received/completed/pending counts and states, across all records |
| GET | `/transfers/{id}` | Participant only | Full metadata, session, signed receipt, history |

```json
{
  "receiver_id": "00000000-0000-4000-8000-000000000001",
  "original_filename": "confidential.txt",
  "mime_type": "text/plain",
  "file_size": 312
}
```

The receiver must be an active different identity. File size is bounded by `MAX_UPLOAD_MB`; MIME metadata must have a valid `type/subtype` shape. Filenames containing control characters are rejected; traversal-like display names are sanitized. The original name remains metadata, while storage uses random object IDs.

## Signed key exchange

Every mutation carries this envelope:

```json
{
  "metadata": { "protocol": "secureshare-x/v1", "purpose": "..." },
  "signature": "standard-base64-RSA-PSS-signature"
}
```

| Method | Path | Who | Purpose/result |
|---|---|---|---|
| GET | `/sessions` | Authenticated participant | Own public sessions |
| POST | `/sessions/initiate` | Sender | Signed `DHMetadata`, purpose `dh-initiate`; PENDING session |
| GET | `/sessions/{id}` | Participant | Unexpired public transcript and signatures |
| POST | `/sessions/{id}/respond` | Receiver | Signed `DHMetadata`, purpose `dh-respond`; RESPONDED |
| POST | `/sessions/{id}/verify` | Sender | Signed `ConfirmMetadata`, purpose `dh-confirm`; ESTABLISHED |

Initiation/response include all fields: `protocol`, `purpose`, `transfer_id`, `session_identifier`, `sender_id`, `receiver_id`, `sender_ephemeral_public_key`, `receiver_ephemeral_public_key`, `timestamp`, `nonce`. Initiation includes explicit `null` for the receiver value. Response adds a base64 32-byte Bob key and binds Alice's original key/IDs/context. Both require integer timestamps and fresh 32-hex-character request nonces.

Confirmation includes `protocol`, `purpose`, `transfer_id`, `session_identifier`, `transcript_sha256`, `timestamp`, and `nonce`. The transcript hash is SHA-256 of canonical `{sender: sender_metadata, receiver: receiver_metadata}`. Clients verify peer signatures independently before accepting or deriving a key.

## Upload, download, and verification

### POST `/transfers/{id}/upload`

Sender only, after ESTABLISHED exchange. Raw body is `ciphertext || 16-byte GCM tag`, with:

```http
Content-Type: application/octet-stream
Authorization: Bearer <token>
X-Transfer-Metadata: <standard-base64 UTF-8 canonical JSON metadata>
X-Transfer-Signature: <standard-base64 RSA-PSS signature over metadata>
```

Signed metadata binds protocol/purpose, transfer/session/participants, safe filename, MIME metadata, plaintext size/hash, ciphertext hash, transcript hash, GCM nonce, and timestamp. Headers have size bounds. The nonce here is base64 of the 12-byte GCM IV. Ciphertext length must equal signed plaintext size plus 16. The API verifies signature, context, freshness, size, and hash, stores ciphertext atomically, and returns AVAILABLE transfer details.

### GET `/transfers/{id}/download`

Receiver only. API rechecks the stored RSA signature and ciphertext hash before serving octet-stream bytes. The download filename is `<transfer-id>.enc`; the browser decrypts and saves the verified original safe filename. AVAILABLE moves to DOWNLOADED; retries in DOWNLOADED/COMPLETED do not repeat state transitions. Uncompleted sessions must remain unexpired. This GET is a ciphertext retrieval, not a replay-sensitive signed mutation.

### POST `/transfers/{id}/verify`

Receiver only, signed receipt envelope. Metadata:

```text
protocol="secureshare-x/v1", purpose="transfer-receipt",
transfer_id, receiver_id,
result=VERIFIED|TAMPERED|SIGNATURE_INVALID|FAILED,
plaintext_sha256=<64 lowercase hex or explicit null>,
timestamp=<integer>, nonce=<fresh 32 hex>
```

The receiver signs after local key/signature/GCM/fingerprint checks. VERIFIED requires DOWNLOADED and a hash equal to the sender's signed declaration, advancing through VERIFIED to COMPLETED. Negative receipts can reject AVAILABLE/DOWNLOADED and create security/audit evidence. A false recipient assertion cannot be independently checked by an end-to-end encrypted server; it is explicitly represented as a signed receipt.

## Observation and health

| Method | Path | Access/result |
|---|---|---|
| GET | `/security/events?limit=100` | Events affecting self or participant transfers, latest first; max 500 |
| GET | `/security/stats` | Own visible totals, `by_type`, and `by_severity` |
| GET | `/security/config` | Safe UI configuration: demos enabled, upload/session/window/cooldown values |
| GET | `/audit?limit=100` | Own actions and participant-transfer actions; max 500; no edit/delete endpoint |
| GET | `/health` | Public boolean app/DB/storage readiness; 200 or 503 |

The root `/health` is an alias of `/api/v1/health`. Event rows include type, severity, description, affected IDs, source IP, created time, sanitized metadata, and correlation ID. Unattributed outsider events remain in the database without being exposed to unrelated accounts.

## Demo-only routes

All require bearer authentication and demo rate limits. They are absent, including from OpenAPI, when `ENABLE_ATTACK_DEMOS=false`.

| POST path | Effect |
|---|---|
| `/demo/transfers/{id}/tamper` | Change one ciphertext byte on a participant-owned AVAILABLE/DOWNLOADED transfer |
| `/demo/transfers/{id}/signature` | Change one byte of the stored sender RSA signature |
| `/demo/transfers/{id}/replay` | Attempt the real nonce guard with a previously consumed operation; expected HTTP 409 |
| `/demo/mitm/plain` | Actual synthetic DH decrypt-and-relay demonstration; returns booleans and explanation |
| `/demo/mitm/authenticated` | Replace a signed DH key; RSA rejection and CRITICAL event |
| `/demo/brute-force` | Real invalid login attempts against self; statuses include 429 after threshold |
| `/demo/reset-cooldown` | Clear only the current demo identity's temporary account cooldown |

MITM routes return controlled experiment results, so a blocked simulated attack returns HTTP 200 with `attacker_succeeded=false`; this differs from an invalid real signed exchange, which returns a rejecting error.

## Error contract and status codes

```json
{
  "error": "SIGNATURE_VERIFICATION_FAILED",
  "message": "The supplied digital signature could not be verified.",
  "request_id": "generated-correlation-uuid"
}
```

| HTTP | Representative errors |
|---|---|
| 400 | Signature verification, expired timestamp/challenge, malformed crypto/context |
| 401 | Authentication required, invalid credentials, expired token |
| 403 | Participant attempts the other role's operation |
| 404 | Nonparticipant resource lookup, missing encrypted object, disabled demo |
| 409 | Replay, idempotency conflict, expired session, invalid state, database unique conflict |
| 413 | Upload/request size limit |
| 415 | Raw encrypted upload has wrong content type |
| 422 | Invalid strict schema/UUID/hash/metadata |
| 429 | IP window/account cooldown, with `Retry-After` |
| 503 | Storage/database unavailable or degraded health |
| 500 | Sanitized unexpected error, without stack trace/body secrets |

Read-only list routes are bounded and participant-scoped. An unauthenticated global security dashboard, plaintext file API, server private-key store, key reset, and arbitrary client-specified state mutation API are deliberately absent.
