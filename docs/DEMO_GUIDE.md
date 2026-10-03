# Live demo and viva guide

Use only disposable accounts/files inside the application. The lab has no external-target attack controls. Native setup commands are in [README.md](../README.md). Allow roughly 12–15 minutes to present the complete workflow and attack contrast.

## Preparation

1. Start the API from `backend/` and the Vite client from `frontend/`. Check `/health` and open the React app at one consistent origin, preferably `http://127.0.0.1:5173`.
2. Run `scripts/create_demo_users.py` from the repository root with the root virtual environment. Choose a password; keep it out of committed files. Import encrypted `demo-clients/alice.vault.json` and `bob.vault.json` into separate browser profiles/windows. Eve's identity is available for demonstrating a third user without access to Alice/Bob's transfers.
3. Select RSA challenge authentication for Alice. Explain the server-generated random challenge, full contextual signature, expiry, and one-use consume.
4. Use `docs/samples/confidential.txt`. Keep the sender selection available until upload, or reselect the same original file after a reload.
5. Open browser Identity & keys pages to show public fingerprints and encrypted vault backup, and the server `/docs` to show API groups. Never display unencrypted private key/AES material.

## Demo 1 — normal secure transfer

Alice selects Bob/file in Send file and starts an exchange. Open details and show KEY_EXCHANGE_PENDING, user IDs, and session identifier. Explain that Alice signs her ephemeral X25519 public key, recipient, transfer, time, and nonce.

Bob opens Received files/details and selects Accept key exchange. Show the successful signed response. Bob verifies Alice's registered/pinned public identity before generating and signing a new ephemeral value.

Alice refreshes and chooses Encrypt & upload. Narrate the progress: verify Bob's RSA signature, sign transcript confirmation, compute X25519 shared secret, derive AES-256 using HKDF/transcript context, SHA-256 the plaintext, use a fresh GCM IV, encrypt with AAD, hash ciphertext, sign the complete metadata, and upload ciphertext only.

Bob chooses Verify & download. Show the lifecycle reaching COMPLETED, matching plaintext/ciphertext fingerprints, and Bob's signed receipt. Compare original/downloaded bytes (the automated browser suite does an exact binary comparison). Open Security monitor and Audit log to show the actual actions and request IDs.

**Viva point:** the server verifies public evidence and Bob's receipt; it cannot independently inspect Bob's decrypted plaintext. Retained encrypted client exchange keys permit historical downloads but weaken long-term forward secrecy if the vault is later compromised.

## Demo 2 — ciphertext tampering

Create a **new** transfer and finish upload, leaving it AVAILABLE before Bob verifies. In Alice's Attack lab, select it and click Tamper File. The control changes one byte in the encrypted server object.

Bob's Verify & download rejects it with `FILE_TAMPERING_DETECTED` and state TAMPERED. The API's ciphertext hash check can reject before browser decryption; the AES-GCM unit/browser tests separately prove a modified ciphertext/tag fails AEAD decryption. A package with an incorrect GCM tag but a sender-signed matching ciphertext hash passes the server's public checks and is rejected by the browser's GCM check.

Open the security event and HIGH severity. Explain that SHA-256 is authenticated by RSA, while AES-GCM additionally authenticates ciphertext/AAD under the secret key. No unverified plaintext file is offered.

## Demo 3 — signature forgery

Create another new AVAILABLE transfer. Select it in Attack lab and click Modify Signature. Bob rejects the sender file signature. The browser reports a signed negative receipt when the rejection occurs locally before download; direct API download also checks and rejects the stored signature. Show SIGNATURE_INVALID and its HIGH event.

**Viva point:** changing the signature is detected without revealing or deriving the sender RSA private key. A valid signature from Eve is also rejected as Alice's signature (tested in the API suite).

## Demo 4 — replay

Choose a transfer with a consumed signed operation and click Replay Request. The demo invokes the actual persisted nonce guard. Show HTTP 409 `REPLAY_ATTACK_DETECTED` in the returned result/request ID and HIGH REPLAY_ATTACK in Security monitor.

Explain nonce freshness versus transfer-creation idempotency. Reusing a creation idempotency key/payload returns the existing transfer; reusing a signed mutation nonce does not re-execute it. Consumed nonces survive restart. Challenges are separately one-use.

## Demo 5 — strongest comparison: MITM

Click Simulate MITM on Plain DH. Point out the prominent INSECURE DEMO MODE label and Alice↔Eve↔Bob graph. The result confirms Alice/Eve share one secret, Eve/Bob another, Alice/Bob do not share the same secret, and Eve actually decrypted/re-encrypted the harmless message.

Click Simulate MITM on Authenticated DH. Eve substitutes a public key in previously signed metadata. Show `signature_valid=false`, `attacker_succeeded=false`, and CRITICAL MITM_DETECTED. Describe why the attacker cannot create Alice's valid contextual RSA signature.

**Viva point:** DH establishes a secret with whoever is at the other end. RSA signatures authenticate that endpoint only if its verification public key is authentic. First-use registry trust and independent fingerprint verification remain necessary.

## Demo 6 — credential guessing

While still signed in, choose Run Failed Login Simulation. It calls real Argon2 verification with wrong credentials against the current account, generating failures and a temporary account cooldown. The statuses end in 429. Show BRUTE_FORCE_DETECTED and RATE_LIMIT_EXCEEDED.

Use Reset my demo login cooldown to continue. The button is self-scoped and demo-only. A production limiter would share counters across processes (Redis), rather than the mini-project's one-process IP windows.

## Disable the lab

Set `ENABLE_ATTACK_DEMOS=false` in `backend/.env`, restart, and log in. The Attack lab page explains that controls are disabled. `/api/v1/demo/mitm/plain` returns 404 and no demo routes appear in OpenAPI. Tests explicitly verify both conditions.

## Common problems

| Symptom | Cause and remedy |
|---|---|
| No local identity | Import the matching encrypted vault on the login page |
| Vault cannot unlock | Use its original password; an account password does not reconstruct lost keys |
| Missing exchange key | Restore a backup made after that exchange, or create a new transfer |
| No Encrypt & upload button | Bob has not accepted the pending exchange yet; refresh both windows |
| Session expired | Create a new transfer; unfinished sessions default to 30 minutes |
| Failed transfer cannot be reused | Terminal failure states are intentional; use a fresh disposable transfer |
| HTTP 429 | Wait for the configured IP window/cooldown; demo reset clears account cooldown only |
| Different localhost hostname | Vault storage is origin-specific; return to the same origin or import a backup |
| Reload shows login | Unlocked secrets are intentionally memory-only; sign in to unlock again |
| Browser lacks X25519/secure context | Use a recent supported browser on localhost or HTTPS |

## Questions each member should answer

- Why does RSA-PSS use a randomized signature and why must both sides agree on salt length?
- Why use ephemeral X25519 plus HKDF instead of slicing the DH result?
- What identities/context are bound in each signed message?
- How does GCM AAD protect filename/recipient/context, and why is ciphertext hash excluded from AAD but included in RSA metadata?
- How are 128-bit request nonces different from 96-bit GCM IVs?
- Why does a signed receipt express the receiver's claim rather than independent server knowledge of plaintext?
- Why is plain DH vulnerable, and what key-discovery assumptions remain with authenticated DH?
- How do idempotency, rate limiting, state validation, and transaction rollback improve reliability?
- What can the server see, and what does it never receive?
- Which production controls are documented but not implemented?
