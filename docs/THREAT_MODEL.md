# Threat model

## Scope and assets

The application protects plaintext content during transfer and server-side storage, authenticates participating identities against registered public keys, rejects manipulated/replayed packages, and provides understandable evidence. It is an educational local system with trusted client code and a trusted initial public-key registry.

| Asset | Location | Protection |
|---|---|---|
| Plaintext files | Sender memory; receiver memory/user downloads | AES-GCM before upload; no server plaintext storage |
| RSA private identities | Encrypted client vault and user backups | PBKDF2-SHA256 + AES-GCM; memory-only unlocking |
| Ephemeral/session secrets | Client encrypted vault/memory | X25519 + HKDF; never server-persisted |
| User identities | Database, public registry | Argon2id, challenge signatures, opaque-token authentication |
| Transfer metadata | Database and exchange messages | RSA-PSS signatures, strict contextual binding, GCM AAD |
| Ciphertext | Random encrypted storage objects | AES-GCM and signed ciphertext SHA-256 |
| Audit/security evidence | Database and structured logs | Participant-scoped reads; no update/delete API; ORM audit edit guard |

## Adversaries and controls

| Actor/threat | Attempt | Implemented control | Residual risk |
|---|---|---|---|
| Network eavesdropper | Read file bytes | Client AES-256-GCM; server stores ciphertext | Filenames, identities, sizes, hashes, and timing remain visible; TLS needed beyond localhost |
| MITM attacker | Substitute DH keys | RSA signatures over public values and context; transcript confirmation; pinned fingerprints | Malicious first registry/key discovery or delivered JS requires external trust verification |
| Replay attacker | Resubmit signed operation or challenge | Random nonce, timestamp window, persistent nonce uniqueness, one-use challenges | Database rollback by an administrator could remove replay history |
| Tampering attacker | Alter ciphertext/tag/metadata | Sender RSA signature, GCM tag, ciphertext/plaintext SHA-256 | Availability attacks remain possible |
| Impersonator | Sign as another user | RSA-PSS challenge, public-key signatures, receiver-only receipts | Stolen/unlocked private keys or compromised client break identity |
| Credential guesser | Brute-force passwords | Argon2id, IP windows, account failure counters and temporary cooldown | Same-IP users share quota; unauthenticated attempts can temporarily disrupt a known account |
| Unauthorized outsider | Enumerate/download transfers | Bearer authentication, participant-scoped lookups, receiver-only downloads | Registered directory intentionally exposes active usernames/public keys |
| Malicious registered user | Write other users' objects; replay nonce; fake state | Authoritative participant binding, safe storage IDs, strict state machine, signed metadata, bounds | A legitimate recipient can lie in a signed receipt about its own verification |
| Path traversal attacker | Submit `../`, Windows paths/device names | Sanitized display names; random storage IDs; resolved-root containment check | Symlink/storage directory control by the host administrator is outside the boundary |
| Abusive uploader | Exhaust memory/disk | Bounded creation/streamed reads, IP rate limits, configurable 25 MB cap | No global disk quota, user storage quota, or distributed DoS mitigation |
| Signature forger | Modify signatures/context | Library RSA-PSS verification; constant purpose tags and canonical serialization | Library/implementation vulnerabilities require ongoing dependency updates |
| Database administrator | Rewrite/delete evidence | Append-only through app and ORM hooks | Audit is not an externally anchored tamper-evident ledger |
| Browser XSS/extension | Read unlocked keys and files | React text rendering; no unsafe HTML; encrypted locked vault; Docker static CSP | Trusted code/extension compromise can access browser secrets while unlocked |

## Trust boundaries

1. Browser vault unlock: the password decrypts local secrets; the encrypted backup never travels through the API.
2. Browser/API boundary: only public values, public metadata, signatures, ciphertext, password login credentials, and bearer tokens cross. TLS protects credentials and tokens in a nonlocal deployment.
3. API/database boundary: authenticated identity and validated state determine writes; replay/idempotency invariants have database unique constraints.
4. API/storage boundary: user filenames cannot choose object paths. Objects are ciphertext only.
5. Attack lab boundary: endpoints are authenticated, scoped to participant-owned disposable transfers, and omitted entirely when disabled. MITM messages are synthetic and have no external destination.

## Explicit exclusions and mitigations for deployment

Host compromise, malicious delivered client code, stolen unlocked devices, untrusted first key discovery, malicious recipient honesty, large-scale DoS, and content safety are outside the lab's guarantees. Files are downloaded only after cryptographic verification; the application does not claim that verified content is harmless, does not preview or execute it, and does not classify its real MIME type.

Production should add TLS, independent identity/fingerprint verification or certificates, stronger client isolation/CSP, secure token lifecycle, client key retention/deletion policies, coordinated limits/quotas, external storage reconciliation, PostgreSQL migrations/concurrency controls, externally anchored audit integrity, and an independent protocol/application review.
