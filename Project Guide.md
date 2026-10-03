# SECURESHARE-X — ACTIONABLE IMPLEMENTATION PROMPT

Act as a senior cybersecurity engineer, backend engineer, system architect, and full-stack developer.

Build a **complete working mini-project** named:

# SecureShare-X
### Secure File Exchange with Authenticated Key Exchange, Hybrid Cryptography, Digital Signatures, Attack Detection, Audit Logging, and Reliability Features

This is a Cryptography and Network Security lab project for a 3-member team. Prioritize:

- correct cryptography;
- clear architecture;
- demonstrability;
- security;
- understandable code;
- viva-ready documentation;
- easy local setup.

Do **not stop at scaffolding**. Implement, test, fix, document, and validate the complete system.

---

# 1. TARGET ARCHITECTURE

Use a **modular monolith**.

```text
React Frontend
      |
      v
FastAPI REST API
      |
      +-- Authentication
      +-- User/Public-Key Registry
      +-- Secure Session Manager
      +-- Cryptographic Service
      +-- File Transfer Service
      +-- Security Detection Engine
      +-- Audit Logging
      +-- Storage Service
      +-- Persistence
              |
              v
           SQLite
```

Store encrypted file objects under `storage/`.

**Never persist plaintext files longer than necessary.**

Keep these concerns separate:

- routes/API;
- schemas;
- services/business logic;
- repositories/database;
- cryptography;
- middleware;
- security monitoring;
- storage;
- frontend.

Use service modules such as:

- `AuthService`
- `UserService`
- `CryptoService`
- `SessionService`
- `TransferService`
- `StorageService`
- `SecurityEventService`
- `AuditService`

---

# 2. TECHNOLOGY STACK

## Backend

- Python 3.11+
- FastAPI
- Uvicorn
- SQLAlchemy
- Pydantic
- Python `cryptography`
- Argon2 or bcrypt/passlib
- SQLite for demo
- architecture portable to PostgreSQL

## Frontend

Use:

- React
- Vite
- normal CSS or Bootstrap

Focus on functionality and security visualization rather than complex animations.

## Testing

Use:

- `pytest`
- unit tests
- integration/API tests

---

# 3. IMPLEMENT THE CRYPTOGRAPHIC FOUNDATION

## Step 3.1 — RSA identity

Each user must have:

```text
RSA Private Key -> client only
RSA Public Key  -> registered with server
```

Use RSA for:

- identity;
- authentication;
- digital signatures.

Use:

```text
RSA-PSS + SHA-256
```

Never:

- store plaintext private keys on server;
- implement textbook RSA;
- hardcode private keys.

---

## Step 3.2 — SHA-256

Use SHA-256 for:

- plaintext file fingerprints;
- integrity checks;
- signed metadata;
- HKDF/key-derivation context where appropriate.

Do not use MD5/SHA-1 for real security.

---

## Step 3.3 — Diffie-Hellman

Use **ephemeral DH**, preferably X25519 if supported cleanly by the cryptography library.

Demonstrate both:

```text
Plain DH
→ MITM vulnerable

Authenticated DH
→ DH public values signed with RSA
→ MITM prevented
```

Never derive the AES key by simply slicing the DH result.

Use:

```text
DH Shared Secret
      ↓
HKDF-SHA256
      ↓
AES-256 Session Key
```

Include meaningful context/info in HKDF.

---

## Step 3.4 — AES

Encrypt files using:

```text
AES-256-GCM
```

Generate a fresh cryptographically secure nonce for every encryption.

Store/transmit:

- ciphertext;
- nonce;
- authentication tag where required by library API.

Never use:

- ECB;
- nonce reuse under the same AES key.

---

# 4. DATABASE

Create at least these models.

## `users`

```text
id
username
password_hash
public_key_pem
created_at
is_active
failed_login_attempts
```

## `auth_challenges`

```text
id
user_id
challenge
expires_at
used
created_at
```

## `secure_sessions`

```text
id
sender_id
receiver_id
session_identifier
sender_ephemeral_public_key
receiver_ephemeral_public_key
status
created_at
expires_at
```

Do not unnecessarily store raw session secrets.

## `transfers`

```text
id
sender_id
receiver_id
original_filename
safe_filename
encrypted_storage_path
file_size
plaintext_sha256
ciphertext_sha256   # optional/useful
signature
nonce
timestamp
status
created_at
updated_at
```

## `consumed_nonces`

```text
id
nonce
user_id or transfer_id
created_at
```

## `security_events`

```text
id
event_type
severity
user_id nullable
transfer_id nullable
source_ip nullable
description
metadata_json
created_at
```

## `audit_logs`

```text
id
actor_user_id nullable
action
resource_type
resource_id
request_id
created_at
```

Use database transactions where atomicity matters, e.g.:

```text
create transfer
+
create audit record
```

Rollback on failure.

---

# 5. CONFIGURATION

Use `.env` and create `.env.example`.

Support at least:

```env
APP_ENV=
DATABASE_URL=
MAX_UPLOAD_MB=25
SESSION_EXPIRY_MINUTES=
REPLAY_WINDOW_SECONDS=
RATE_LIMIT_LOGIN=
STORAGE_PATH=
LOG_LEVEL=
ENABLE_ATTACK_DEMOS=true
```

Never commit secrets.

---

# 6. AUTHENTICATION

## Step 6.1 — Registration

Client submits:

```text
username
password
RSA public key
```

Server stores:

- username;
- secure password hash;
- public key.

Private key stays with client.

Optionally provide a safe client-side/local key-generation utility.

---

## Step 6.2 — Challenge-response authentication

Implement:

1. Client requests challenge.
2. Server generates secure random challenge.
3. Store challenge with expiration.
4. Client signs challenge using RSA private key.
5. Client sends signature.
6. Server verifies against registered RSA public key.
7. Mark challenge as used.
8. Reject expired/reused challenges.
9. On success, issue authenticated session/token.

Password login may coexist for educational/demo purposes.

Log:

```text
CHALLENGE_CREATED
CHALLENGE_VERIFIED
```

---

# 7. AUTHENTICATED DH SESSION ESTABLISHMENT

For Alice sending to Bob:

## Alice

1. Generate ephemeral DH/X25519 pair.
2. Create canonical metadata containing:

```text
sender ID
receiver ID
Alice ephemeral public key
timestamp
nonce
session/transfer context
```

3. Sign it using Alice's RSA private key.

## Bob

4. Verify Alice's signature using registered public key.
5. Reject if invalid.
6. Generate Bob's ephemeral DH pair.
7. Sign Bob's DH public value + same contextual information.

## Alice

8. Verify Bob's signature.
9. Reject if invalid.

## Both sides

10. Compute identical DH shared secret.
11. Derive AES-256 key using HKDF-SHA256.

This authenticated exchange must be the normal secure mode.

---

# 8. SECURE FILE TRANSFER

## Sender workflow

Perform:

```text
Select file
↓
Validate filename/type/size
↓
SHA-256 plaintext fingerprint
↓
Authenticated DH session
↓
HKDF-SHA256
↓
AES-256 key
↓
Generate random AES-GCM nonce
↓
AES-256-GCM encryption
↓
Create canonical transfer metadata
↓
RSA-PSS signature
↓
Upload ciphertext + crypto metadata only
```

Signed metadata should bind important values including:

- sender;
- receiver;
- file hash;
- transfer ID;
- timestamp;
- nonce;
- DH/session information.

---

## Receiver workflow

Before accepting a transfer:

1. Validate timestamp.
2. Validate nonce has not been consumed.
3. Verify sender RSA signature.
4. Verify authenticated DH session.
5. Re-derive AES key.
6. AES-GCM decrypt.
7. Recompute SHA-256.
8. Compare fingerprint.
9. Mark transfer verified/completed only if **all checks succeed**.

If any check fails:

```text
Reject transfer
+
record security event
+
write audit log
+
show understandable frontend error
```

---

# 9. TRANSFER STATE MACHINE

Implement validated transitions.

Suggested states:

```text
CREATED
↓
KEY_EXCHANGE_PENDING
↓
KEY_ESTABLISHED
↓
ENCRYPTED
↓
UPLOADED
↓
AVAILABLE
↓
DOWNLOADED
↓
VERIFIED
↓
COMPLETED
```

Failure states:

```text
REJECTED
TAMPERED
SIGNATURE_INVALID
REPLAY_REJECTED
FAILED
```

Never allow arbitrary/invalid transitions.

Detect suspicious state transitions.

---

# 10. REPLAY PROTECTION

Security-sensitive operations must carry:

```text
transfer ID
timestamp
random nonce
```

Maintain consumed nonces.

Reject:

- duplicate nonce;
- expired/out-of-window timestamps.

Generate:

```text
REPLAY_ATTACK
Severity: HIGH
```

---

# 11. IDEMPOTENCY

`POST /transfers` must accept something like:

```http
Idempotency-Key: <UUID>
```

Repeated requests with the same key must return/reuse the existing transfer rather than create duplicates.

---

# 12. RATE LIMITING

Implement a simple in-memory rate limiter for the mini-project.

Apply especially to:

- login;
- challenge generation;
- signature verification;
- uploads.

Return:

```http
429 Too Many Requests
```

and create:

```text
RATE_LIMIT_EXCEEDED
```

Document that production would normally use Redis/distributed rate limiting.

---

# 13. INPUT AND FILE SECURITY

Validate:

- username;
- IDs;
- filename;
- MIME metadata;
- file size;
- timestamp;
- public-key format;
- cryptographic parameters.

Sanitize filenames.

Prevent:

```text
../
directory traversal
unsafe storage paths
```

Default upload limit:

```text
25 MB
```

Make configurable.

Use chunked hashing/file processing where practical.

For encryption, correctness is more important than implementing complicated streaming GCM. If necessary, enforce the size limit and safely encrypt in memory while documenting the scalability limitation.

---

# 14. STORAGE ABSTRACTION

Implement something like:

```text
StorageService
    |
    +-- LocalEncryptedStorage
```

Design so it could later become:

```text
S3EncryptedStorage
```

without rewriting transfer logic.

Only encrypted content should be stored.

---

# 15. AUDIT LOGGING

Record important operations including:

```text
USER_REGISTERED
LOGIN_SUCCESS
LOGIN_FAILED
CHALLENGE_CREATED
CHALLENGE_VERIFIED
TRANSFER_CREATED
DH_INITIATED
DH_VERIFIED
FILE_UPLOADED
FILE_DOWNLOADED
SIGNATURE_VALID
SIGNATURE_INVALID
FILE_INTEGRITY_VALID
FILE_TAMPERING_DETECTED
REPLAY_ATTACK
RATE_LIMIT_EXCEEDED
MITM_DETECTED
```

Audit entries should behave as immutable-style records.

---

# 16. SECURITY MONITORING

Implement a lightweight **rule-based**, not ML-based, detector.

Detect:

- repeated login failures;
- duplicate nonces;
- invalid signatures;
- challenge reuse;
- expired timestamps;
- integrity failures;
- MITM demo attempts;
- excessive uploads;
- malformed keys;
- suspicious transfer-state changes.

Severity levels:

```text
INFO
LOW
MEDIUM
HIGH
CRITICAL
```

Example mapping:

```text
Successful login       -> INFO
Repeated failed login  -> MEDIUM
Invalid signature      -> HIGH
Replay                 -> HIGH
MITM                    -> CRITICAL
```

Expose statistics/events to frontend.

---

# 17. STRUCTURED LOGGING + OBSERVABILITY

Logs should contain useful fields such as:

```text
event_type
timestamp
user_id
transfer_id
source_ip
severity
status
request_id
```

Never log:

- passwords;
- private keys;
- plaintext AES/session keys;
- decrypted file contents.

Generate a correlation/request ID for each API request.

Include request ID in:

- logs;
- audit entries;
- relevant error responses.

Implement:

```http
GET /health
GET /api/v1/health
```

Check:

- application;
- database;
- storage.

Do not leak sensitive internals.

---

# 18. CENTRALIZED ERRORS

Implement global/central FastAPI exception handling.

Return errors such as:

```json
{
  "error": "SIGNATURE_VERIFICATION_FAILED",
  "message": "The supplied digital signature could not be verified.",
  "request_id": "..."
}
```

Never expose stack traces to normal frontend users.

---

# 19. ATTACK LAB

Create a dedicated **Attack Demonstration** area.

Attack simulation must operate **only inside SecureShare-X**.

Clearly separate:

```text
NORMAL MODE
```

from:

```text
DEMO ATTACK MODE
```

Use:

```env
ENABLE_ATTACK_DEMOS=true
```

Disable `/demo` attack endpoints when false.

---

# 20. ATTACK DEMONSTRATIONS

## Attack A — Ciphertext tampering

Action:

```text
Tamper Ciphertext
```

Modify one byte of stored ciphertext/package.

Expected:

```text
AES-GCM authentication/decryption failure
and/or integrity mismatch

FILE_TAMPERING_DETECTED
Severity: HIGH
```

Reject file.

---

## Attack B — Signature tampering

Modify sender signature.

Expected:

```text
RSA verification fails
SIGNATURE_INVALID
file rejected
```

---

## Attack C — Replay

Replay a previously processed nonce/request.

Expected:

```text
REPLAY_ATTACK_DETECTED
request rejected
transfer not reprocessed
```

---

## Attack D — MITM on plain DH

Provide an intentionally insecure educational mode.

Show:

```text
Alice <-> Eve
Eve   <-> Bob
```

Eve establishes separate secrets with each participant.

Label prominently:

```text
INSECURE DEMO MODE
```

---

## Attack E — MITM on authenticated DH

Eve replaces a DH public key.

Expected:

```text
RSA signature verification fails
MITM ATTEMPT DETECTED
Severity: CRITICAL
```

Make the contrast between plain and authenticated DH one of the main live demos.

---

## Attack F — brute-force login

Simulate repeated invalid login attempts.

Detect:

```text
N failures within configured time window
```

Then:

- create event;
- temporarily throttle;
- return HTTP 429.

Do not permanently lock users during the demo unless resettable.

---

# 21. FRONTEND

Create the following pages.

## Login / Register

Support:

- registration;
- login;
- challenge-response;
- public-key registration;
- local key generation/download if implemented.

Warn clearly:

```text
Never upload your private key to the server.
```

---

## Dashboard

Show:

- welcome/user info;
- files sent;
- files received;
- successful transfers;
- pending transfers;
- security alerts;
- recent activity.

---

## Send File

Allow:

- receiver selection;
- file selection.

Display:

```text
file size
SHA-256 fingerprint
authentication status
key-exchange status
encryption status
signature status
upload status
```

---

## Received Files

Display:

```text
sender
filename
timestamp
verification status
download action
```

---

## Transfer Details

Visualize:

```text
Authenticated
↓
DH Key Exchange
↓
HKDF Key Derivation
↓
AES-256-GCM Encryption
↓
SHA-256 Fingerprint
↓
RSA Digital Signature
↓
Transfer
↓
Signature Verification
↓
Decryption
↓
Integrity Verification
```

Use obvious green/red status indicators.

---

## Security Dashboard

Show:

- total security events;
- failed logins;
- replay attacks;
- tampering attempts;
- invalid signatures;
- MITM detections;
- rate-limit violations;
- severity;
- recent event table.

---

## Attack Demonstration

Provide controls:

```text
Normal Secure Transfer
Tamper File
Replay Request
Modify Signature
Simulate MITM on Plain DH
Simulate MITM on Authenticated DH
Run Failed Login Simulation
```

Each demo should explain:

```text
what attacker attempted
what security mechanism responded
why the attack succeeded/failed
```

---

# 22. UI QUALITY

Use:

- responsive layout;
- sidebar/navbar;
- cards;
- tables;
- badges;
- modals where useful;
- loading states;
- clear alerts.

Professional enough for project evaluation.

Do not waste time on elaborate animations.

---

# 23. API

Version everything under:

```text
/api/v1/
```

Implement approximately:

```http
POST /api/v1/auth/register
POST /api/v1/auth/login
POST /api/v1/auth/challenge
POST /api/v1/auth/challenge/verify

GET  /api/v1/users
GET  /api/v1/users/{id}/public-key

POST /api/v1/sessions/initiate
POST /api/v1/sessions/{id}/respond
POST /api/v1/sessions/{id}/verify

POST /api/v1/transfers
POST /api/v1/transfers/{id}/upload
GET  /api/v1/transfers/sent
GET  /api/v1/transfers/received
GET  /api/v1/transfers/{id}
GET  /api/v1/transfers/{id}/download
POST /api/v1/transfers/{id}/verify

GET  /api/v1/security/events
GET  /api/v1/security/stats

GET  /api/v1/audit
GET  /api/v1/health
```

Demo-only:

```text
/api/v1/demo/*
```

Disable these when attack demos are off.

---

# 24. SECURITY RULES

Never:

- hardcode keys;
- store plaintext passwords;
- store server-side plaintext private keys;
- log passwords/private keys/session secrets/plaintext files;
- create custom crypto algorithms;
- use AES-ECB;
- use insecure randomness;
- reuse GCM nonce under the same key;
- use textbook RSA;
- trust filenames;
- allow path traversal;
- permit unlimited uploads;
- silently accept invalid signatures;
- ignore integrity failures.

Use:

```text
secrets / secure randomness
Argon2 or bcrypt
RSA-PSS
SHA-256
X25519/DH
HKDF-SHA256
AES-256-GCM
strict validation
```

---

# 25. THREAT MODEL

Document these assets:

- plaintext files;
- RSA private keys;
- session secrets;
- identities;
- transfer metadata;
- audit records.

Threat actors:

- network attacker;
- MITM attacker;
- replay attacker;
- malicious registered user;
- unauthorized outsider.

Threats:

- eavesdropping;
- MITM;
- replay;
- tampering;
- impersonation;
- credential guessing;
- path traversal;
- abusive uploads;
- signature forgery.

Map threats to controls:

```text
Eavesdropping
-> AES-256-GCM

MITM
-> Authenticated DH + RSA signatures

Replay
-> nonce + timestamp

Tampering
-> AES-GCM + SHA-256

Impersonation
-> RSA challenge-response/signatures

Password guessing
-> password hashing + rate limiting

Unauthorized modification
-> signatures + audit logs
```

---

# 26. RELIABILITY

Correctly handle:

- duplicate requests;
- interrupted/failed uploads;
- invalid transfer states;
- expired sessions;
- missing files;
- DB errors;
- invalid keys;
- corrupted ciphertext;
- wrong signatures.

Never leave inconsistent state when an operation partially fails.

---

# 27. PROJECT STRUCTURE

Use approximately:

```text
secureshare-x/
│
├── backend/
│   ├── app/
│   │   ├── main.py
│   │   ├── api/v1/
│   │   │   ├── auth.py
│   │   │   ├── users.py
│   │   │   ├── sessions.py
│   │   │   ├── transfers.py
│   │   │   ├── security.py
│   │   │   ├── audit.py
│   │   │   └── demo.py
│   │   ├── core/
│   │   │   ├── config.py
│   │   │   ├── security.py
│   │   │   ├── crypto.py
│   │   │   ├── logging.py
│   │   │   └── exceptions.py
│   │   ├── models/
│   │   ├── schemas/
│   │   ├── services/
│   │   │   ├── auth_service.py
│   │   │   ├── crypto_service.py
│   │   │   ├── session_service.py
│   │   │   ├── transfer_service.py
│   │   │   ├── storage_service.py
│   │   │   ├── security_event_service.py
│   │   │   └── audit_service.py
│   │   ├── repositories/
│   │   ├── middleware/
│   │   │   ├── request_id.py
│   │   │   └── rate_limit.py
│   │   └── db/
│   ├── tests/
│   ├── storage/
│   ├── requirements.txt
│   └── .env.example
│
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   ├── pages/
│   │   ├── services/
│   │   ├── hooks/
│   │   └── utils/
│   ├── package.json
│   └── vite.config.js
│
├── docs/
│   ├── ARCHITECTURE.md
│   ├── CRYPTOGRAPHY.md
│   ├── THREAT_MODEL.md
│   ├── API.md
│   ├── DEMO_GUIDE.md
│   └── SYSTEM_DESIGN.md
│
├── scripts/
│   ├── create_demo_users.py
│   └── reset_demo.py
│
├── .gitignore
├── README.md
└── docker-compose.yml
```

Improve structure where useful, while preserving separation of concerns.

---

# 28. TESTS

At minimum test:

### Authentication

- registration;
- duplicate username rejection;
- password hashing;
- challenge generation;
- challenge expiration;
- challenge replay rejection.

### RSA

- valid signature;
- invalid signature.

### DH/HKDF

- matching DH shared secrets;
- derived key equality;
- HKDF behavior.

### AES/SHA

- AES encryption/decryption;
- altered ciphertext rejection;
- SHA-256 verification.

### Transfer Security

- nonce replay rejection;
- authenticated transfer;
- signature modification;
- ciphertext modification;
- MITM demo behavior.

### System Design

- rate limiting;
- idempotency;
- allowed state transitions;
- invalid state transitions;
- upload size limit;
- filename sanitization;
- audit-log creation;
- security-event creation.

---

# 29. DOCUMENTATION

Create an excellent `README.md` containing:

- overview;
- problem statement;
- features;
- architecture;
- crypto workflow;
- stack;
- project structure;
- installation;
- backend setup;
- frontend setup;
- user/key creation;
- file transfer;
- attack demos;
- assumptions;
- limitations;
- tests;
- screenshot placeholders;
- future work;
- team division.

Create:

```text
docs/ARCHITECTURE.md
docs/CRYPTOGRAPHY.md
docs/THREAT_MODEL.md
docs/API.md
docs/DEMO_GUIDE.md
docs/SYSTEM_DESIGN.md
```

`SYSTEM_DESIGN.md` must cover:

- functional requirements;
- non-functional requirements;
- architecture;
- APIs;
- database;
- transfer state machine;
- security architecture;
- storage;
- idempotency;
- rate limiting;
- errors;
- observability;
- scalability;
- failure scenarios;
- future production architecture.

---

# 30. MERMAID DIAGRAMS

Create:

1. overall architecture;
2. secure file-transfer sequence;
3. authenticated-DH sequence;
4. replay detection;
5. MITM comparison;
6. transfer state machine;
7. ER/database diagram.

---

# 31. LIVE DEMO DATA

Create:

```text
Alice
Bob
Eve
```

Provide scripts to create/reset demo data.

Use a test file such as:

```text
confidential.pdf
```

---

# 32. LIVE DEMO SEQUENCE

## Demo 1 — Normal transfer

Show:

```text
Alice authenticated
↓
Bob selected
↓
Authenticated DH successful
↓
Shared secret generated
↓
HKDF key derived
↓
SHA-256 fingerprint generated
↓
AES-256-GCM encryption successful
↓
RSA-PSS signature generated
↓
Encrypted upload successful
↓
Bob verifies RSA signature
↓
Bob decrypts
↓
SHA-256 matches
↓
Transfer completed
```

## Demo 2 — Tampering

```text
alter ciphertext
→ AES-GCM/integrity failure
→ FILE_TAMPERING_DETECTED
```

## Demo 3 — Replay

```text
reuse nonce
→ REPLAY_ATTACK_DETECTED
```

## Demo 4 — Signature forgery

```text
modify signature
→ SIGNATURE_INVALID
```

## Demo 5 — MITM

First:

```text
Plain DH
Alice <-> Eve <-> Bob
attack succeeds conceptually
```

Then:

```text
Authenticated DH
Eve replaces DH public key
→ RSA verification failure
→ MITM_DETECTED
```

This should be the strongest viva/live-demo feature.

---

# 33. IMPLEMENTATION ORDER

Proceed automatically through these phases.

## Phase 1 — Foundation

Implement:

- folders;
- configuration;
- DB connection;
- models;
- migrations/init mechanism;
- error handling;
- logging;
- request IDs.

## Phase 2 — Authentication

Implement:

- registration;
- password login;
- RSA public-key registration;
- challenge-response.

## Phase 3 — Crypto

Implement/test:

- RSA-PSS signing/verification;
- X25519/DH;
- HKDF-SHA256;
- AES-256-GCM;
- SHA-256;
- secure nonce generation.

## Phase 4 — Transfer

Implement:

- secure sessions;
- transfer records;
- state machine;
- encrypted storage;
- idempotency;
- upload/download;
- verification.

## Phase 5 — Security

Implement:

- nonce replay prevention;
- timestamps;
- rate limiting;
- security-event rules;
- audit logs.

## Phase 6 — Attack Lab

Implement:

- file tampering;
- signature modification;
- replay;
- plain-DH MITM;
- authenticated-DH MITM;
- failed-login simulation.

## Phase 7 — Frontend

Build all required pages and visual security pipeline.

## Phase 8 — Tests

Run complete test suite and fix failures.

## Phase 9 — Documentation

Write all README/docs/diagrams/demo instructions.

## Phase 10 — End-to-End Validation

Run complete application and verify every core feature.

Do not stop between phases waiting for approval unless external information is genuinely required.

---

# 34. CODE QUALITY

Use:

- Python type hints;
- descriptive names;
- small functions;
- reusable crypto logic;
- service separation;
- FastAPI dependency injection where appropriate;
- docstrings where useful;
- consistent formatting.

Avoid:

- huge route handlers;
- duplicated crypto functions;
- magic constants;
- hardcoded filesystem paths;
- unnecessary enterprise abstractions.

---

# 35. FUTURE SCALABILITY — DOCUMENT ONLY

Do **not** implement this infrastructure now.

Document possible production evolution:

```text
Load Balancer
      |
FastAPI Instances
      |
      +-- Redis
      |    ├── distributed rate limiting
      |    └── cache/session data
      |
      +-- PostgreSQL
      |
      +-- S3 / MinIO
      |
      +-- Message Queue
           └── async audit/security processing
```

Keep current implementation self-contained and easy to run.

Do not add Prometheus/Grafana unless all core functionality is already complete.

---

# 36. DOCKER

If practical, include:

```text
backend/Dockerfile
frontend/Dockerfile
docker-compose.yml
```

But also support normal non-Docker startup.

---

# 37. TEAM DIVISION

Document:

## Member 1 — Authentication & Identity

- RSA keys;
- challenge-response;
- signatures;
- verification;
- identity/authentication.

## Member 2 — Secure Transfer/Cryptography

- DH/X25519;
- HKDF;
- AES-GCM;
- SHA-256;
- secure transfer flow.

## Member 3 — Backend/System Design/Security Monitoring

- FastAPI;
- DB;
- transfer state handling;
- rate limiting;
- idempotency;
- audit logs;
- security detection;
- attack lab;
- frontend integration.

All members must still understand the complete workflow.

---

# 38. FINAL VALIDATION CHECKLIST

Before declaring completion, actually run and verify:

```text
[ ] Backend tests pass
[ ] Frontend builds successfully
[ ] Backend imports work
[ ] API starts
[ ] Frontend starts
[ ] Database initializes
[ ] Demo users can be created
[ ] Alice -> Bob secure transfer works
[ ] Downloaded plaintext exactly matches original
[ ] Tampered ciphertext rejected
[ ] Modified signature rejected
[ ] Replay rejected
[ ] Plain-DH MITM demo works as insecure example
[ ] Authenticated-DH MITM attempt rejected
[ ] Rate limiting works
[ ] HTTP 429 produced appropriately
[ ] Idempotency prevents duplicate transfers
[ ] State validation works
[ ] Audit records generated
[ ] Security events generated
[ ] Security dashboard displays real data
[ ] Health endpoint works
[ ] Demo endpoints disabled when configured off
[ ] README setup instructions verified
```

If something fails:

```text
Find cause
→ fix code
→ rerun tests
→ rerun validation
```

Do not merely describe the fix.

Implement it.

---

# 39. REQUIRED FINAL REPOSITORY OUTPUT

Repository must contain:

- working backend;
- working React frontend;
- database initialization;
- authentication;
- challenge-response authentication;
- RSA key/signature handling;
- authenticated DH/X25519;
- HKDF-SHA256;
- AES-256-GCM;
- SHA-256 verification;
- encrypted file storage;
- transfer state machine;
- replay prevention;
- rate limiting;
- idempotency;
- structured logs;
- audit logs;
- security-event engine;
- attack demonstrations;
- security dashboard;
- health checks;
- automated tests;
- README;
- API documentation;
- architecture documentation;
- crypto documentation;
- threat model;
- system-design document;
- demo guide;
- `.env.example`;
- dependency files;
- optional Docker support.

---

# 40. FINAL RESPONSE FORMAT

Only after implementation and validation, provide:

1. what was implemented;
2. repository structure;
3. exact backend startup commands;
4. exact frontend startup commands;
5. demo-user setup command;
6. normal secure-transfer demo procedure;
7. attack-demo procedure;
8. test command + actual results;
9. important architectural/security decisions;
10. known limitations.

Never claim something works unless the code exists and it was actually validated.

---

# CORE PRINCIPLE

SecureShare-X must **not** become merely an:

```text
"AES file encryption website"
```

The project must visibly demonstrate the complete lifecycle:

```text
IDENTITY
↓
AUTHENTICATION
↓
AUTHENTICATED KEY EXCHANGE
↓
SESSION-KEY DERIVATION
↓
ENCRYPTION
↓
DIGITAL SIGNATURE
↓
SECURE TRANSFER
↓
INTEGRITY VERIFICATION
↓
REPLAY PROTECTION
↓
SECURITY MONITORING
↓
AUDIT LOGGING
↓
ATTACK DEMONSTRATION
↓
RELIABLE SYSTEM DESIGN
```

Keep the architecture and implementation understandable enough that all three students can explain every major component during a cybersecurity viva.