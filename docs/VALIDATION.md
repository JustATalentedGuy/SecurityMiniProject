# Validation report

Validated locally on **3 October 2026 (Asia/Calcutta)**. This report describes executed checks and environmental limitations, rather than treating generated code as proof.

## Environment

- Windows, Python **3.12.1** in the project's `.venv`, Node **24.16.0**.
- FastAPI **0.135.1**, SQLAlchemy **2.0.48**, `cryptography` **50.0.0**, Pydantic Settings **2.14.2**.
- React **19.2.4**, Vite **7.3.6**, Vitest **4.1.11**, React Router **7.18.4**; full frontend dependency resolution in `package-lock.json`.
- Playwright **1.58.2** driving installed Google Chrome headlessly with `SSX_BROWSER_CHANNEL=chrome`.

## Executed results

| Check | Actual result |
|---|---|
| `pytest -q --cov=app --cov-report=term-missing` from backend | **63 passed**, **96% application statement coverage**, 42.13 seconds |
| `ruff check backend scripts` from root | Passed |
| `ruff format --check backend scripts` from root | Passed; 54 files formatted consistently |
| `python scripts/validate_end_to_end.py` | Passed against a real isolated Uvicorn process |
| `npm test` | **5 passed** Web Crypto/vault test groups |
| `npm run build` | Passed; React production bundle generated |
| `npm run format:check` | Passed |
| `npm audit` | **0 known vulnerabilities** in resolved frontend packages |
| `pip-audit -r backend/requirements.txt` | **No known vulnerabilities found** in resolved backend runtime requirements |
| `npm run test:e2e` with installed Chrome | **6 passed** browser workflows |
| `docker compose config -q` | Passed configuration validation |

The Python suite emits one upstream Starlette deprecation warning about its HTTPX TestClient transport. It does not indicate a failed test or an application error. The suite uses the guide's HTTPX/FastAPI testing approach. Future dependency maintenance can migrate the test transport when appropriate.

Initial dependency audit findings were fixed before delivery: Pydantic Settings and cryptography were upgraded, unused multipart parsing was removed from runtime requirements, React Router/Vite/Vitest were updated, and esbuild was overridden to the patched **0.28.1** version. Dependency audit results are point-in-time checks rather than a guarantee about future advisories.

## Browser workflows actually exercised

1. Register Alice/Bob in separate browser contexts; Alice starts an RSA-signed exchange; Bob verifies/responds; Alice confirms, derives/encrypts/signs/uploads; Bob verifies/decrypts, sends a signed receipt, and downloads **exactly identical bytes**.
2. Corrupt stored ciphertext, modify the sender signature, and replay a consumed operation; observe actual rejection and real security/audit records.
3. Act as a malicious legitimate sender by altering a GCM tag, updating its ciphertext hash, and signing the changed metadata with Alice's real local key. Public API checks accept that correctly signed package; Bob's **actual AES-GCM decryption rejects it**, sends a negative signed receipt, and never offers plaintext.
4. Perform the actual plain-DH interception/relay, authenticated-DH substitution rejection, real invalid-password simulation ending in HTTP 429, and self-scoped cooldown reset.
5. Download an encrypted vault backup, remove local vault storage, import that backup, authenticate with an RSA challenge, reload/lock, and unlock again.
6. Verify a **390×844** mobile workspace has no document overflow and no browser JavaScript exceptions across the suite.

Screenshots were captured from those runs: login, dashboard, transfer lifecycle, security monitor, attack lab, and mobile. They contain disposable public demonstration metadata, no private keys or account passwords.

## Real-process HTTP validation

The standalone validator starts an isolated server on port 8011 with a temporary SQLite database/storage directory. It runs the demo-user creation script **twice**, verifies preserved Alice/Bob/Eve identities and encrypted client vaults, authenticates each with a signed challenge, performs a complete authenticated transfer, and verifies plaintext byte equality. It then exercises ciphertext/signature corruption, replay, both MITM demonstrations, login cooldown/429, audit reads, and security statistics.

Separate Python tests invoke schema initialization twice to verify non-destructive behavior, exercise the restricted offline reset, confirm ordinary files are preserved by reset, prove atomic concurrent authentication counters, simulate storage and database commit failures, and validate encrypted-object cleanup and retry.

## Guide final validation checklist

| Requirement | Evidence |
|---|---|
| Backend tests/imports/API startup | 63-test suite, real Uvicorn validator, browser API server |
| Frontend build/startup | Production build and Playwright-managed Vite server |
| Database initializes | API lifespan; schema-init subprocess test |
| Demo Alice/Bob/Eve can be created | Actual HTTP script invocation twice with encrypted local vaults |
| Alice → Bob authenticated transfer | Python API suite, real HTTP validator, two-context browser workflow |
| Download plaintext matches original | Exact binary comparison in real HTTP and browser tests |
| Ciphertext/GCM tampering rejected | AES primitive test, stored-file attack, malicious-sender GCM browser test |
| Signature modification rejected | Primitive/API/browser signature attacks |
| Replay/challenge reuse rejected | Persistent nonce, receipt replay, challenge replay and demo tests |
| Plain-DH MITM works as insecure example | Actual decrypt/relay booleans and browser lab result |
| Authenticated-DH MITM blocked | RSA substitution tests and CRITICAL lab event |
| Rate limiting/HTTP 429 | Source-IP limit, account cooldown, actual browser simulation |
| Idempotency | Same-key same-payload reuse and conflicting-payload rejection |
| Valid/invalid states | Every normal transition, terminal failures, unauthorized mutation and early receipt checks |
| Audit/security evidence | Database assertions, APIs and live browser security monitor |
| Dashboard uses real data | Actual transfer/event/aggregate endpoints rendered and captured |
| Health | Both endpoints, degraded-storage case, actual running process |
| Demo endpoints disabled | 404 and omission from OpenAPI when flag is false |
| Native setup/init/reset commands | Executed virtual-environment/dependency setup, server startup, scripts and tests |

## Environmental and architectural limitations

Docker configuration and Dockerfiles are supplied, but **container images were not built or run**: Docker Desktop's Linux engine pipe was unavailable because its daemon was not running. Native execution, both servers, the full transfer, and all attack checks were validated. Do not interpret Compose syntax validation as container runtime validation.

Playwright's Chromium download did not complete on this host. The complete browser suite instead used the installed Chrome through the documented channel option. CI uses Playwright's normal Linux Chromium installation; the GitHub Actions run must be observed independently after pushing rather than inferred from local results.

The implementation's stated limits still apply: trusted initial public registry/client code, localhost or HTTPS, bounded memory/file size, one-process IP limiting, retained encrypted client exchange keys, signed recipient claims rather than server plaintext knowledge, and application-level audit immutability. See [THREAT_MODEL.md](THREAT_MODEL.md) and [SYSTEM_DESIGN.md](SYSTEM_DESIGN.md).
