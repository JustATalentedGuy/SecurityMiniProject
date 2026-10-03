import secrets

from cryptography.hazmat.primitives.asymmetric import rsa, x25519
from sqlalchemy import select

from app.core import crypto
from app.core.exceptions import AppError
from app.models import ConsumedNonce
from app.schemas import Login
from app.services.auth_service import AuthService
from app.services.crypto_service import CryptoService
from app.services.transfer_service import TransferService


class DemoService:
    def __init__(self, db, settings, storage, events, audit):
        self.db, self.settings, self.storage, self.events, self.audit = (
            db,
            settings,
            storage,
            events,
            audit,
        )
        self.transfers = TransferService(db, settings, storage, events, audit)

    def corrupt(self, actor, transfer_id: str, signature: bool) -> dict:
        transfer = self.transfers.repository.transfer(transfer_id, actor)
        if transfer.status not in {"AVAILABLE", "DOWNLOADED"}:
            raise AppError(
                "INVALID_DEMO_STATE",
                "Choose a disposable uploaded transfer before verification.",
                409,
            )
        if signature:
            value = bytearray(crypto.unb64(transfer.signature))
            value[0] ^= 1
            transfer.signature = crypto.b64(bytes(value))
        else:
            content = bytearray(self.storage.read(transfer.encrypted_storage_path))
            content[0] ^= 1
            # Replace atomically; preserve storage compensation if the DB commit fails.
            object_id = self.storage.write(bytes(content))
            previous = transfer.encrypted_storage_path
            transfer.encrypted_storage_path = object_id
            try:
                self.audit.record("DEMO_CIPHERTEXT_MODIFIED", actor.id, "transfer", transfer.id)
                self.db.commit()
            except Exception:
                self.db.rollback()
                self.storage.delete(object_id)
                raise
            self.storage.delete(previous)
        self.audit.record(
            "DEMO_SIGNATURE_MODIFIED" if signature else "DEMO_TAMPERED",
            actor.id,
            "transfer",
            transfer.id,
        )
        return {
            "attack": "signature modification" if signature else "ciphertext modification",
            "message": "One byte was changed. The receiver's next download will run the real verification checks.",
            "transfer_id": transfer.id,
            "mode": "DEMO ATTACK MODE",
        }

    def replay(self, actor, transfer_id: str) -> None:
        transfer = self.transfers.repository.transfer(transfer_id, actor)
        nonce = self.db.scalar(
            select(ConsumedNonce)
            .where(ConsumedNonce.user_id == actor.id, ConsumedNonce.transfer_id == transfer.id)
            .order_by(ConsumedNonce.id.desc())
        )
        if not nonce:
            raise AppError(
                "NO_REQUEST_TO_REPLAY", "Perform a signed operation on this transfer first.", 409
            )
        import time

        CryptoService(self.db, self.settings, self.events).fresh(
            actor.id, int(time.time()), nonce.nonce, nonce.purpose, transfer.id
        )

    def mitm(self, actor, authenticated: bool) -> dict:
        # These isolated demo keys are transient and never represent registered identities.
        alice, bob, eve_a, eve_b = [x25519.X25519PrivateKey.generate() for _ in range(4)]
        secret_a = alice.exchange(eve_a.public_key())
        secret_ea = eve_a.exchange(alice.public_key())
        secret_b = bob.exchange(eve_b.public_key())
        secret_eb = eve_b.exchange(bob.public_key())
        if authenticated:
            identity = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            metadata = {
                "protocol": crypto.PROTOCOL,
                "purpose": "isolated-mitm-demo",
                "alice_ephemeral": crypto.b64(alice.public_key().public_bytes_raw()),
                "nonce": secrets.token_hex(16),
            }
            signature = crypto.sign(identity, crypto.canonical(metadata))
            metadata["alice_ephemeral"] = crypto.b64(eve_b.public_key().public_bytes_raw())
            valid = crypto.verify(
                crypto.public_pem(identity.public_key()), signature, crypto.canonical(metadata)
            )
            self.events.record(
                "MITM_DETECTED",
                "CRITICAL",
                "Authenticated DH demo rejected Eve's substituted public value using RSA-PSS.",
                actor.id,
            )
            return {
                "mode": "AUTHENTICATED DH",
                "attacker_succeeded": valid,
                "signature_valid": valid,
                "mechanism": "RSA-PSS binds the ephemeral key to its signer and context.",
                "explanation": "Eve replaced Alice's DH public value. Verification of the original signature failed before accepting a shared key.",
            }
        transcript = crypto.sha256(b"isolated plain DH demo")
        ka, kea, kb, keb = [
            crypto.derive_key(secret, "isolated-demo", transcript)
            for secret in (secret_a, secret_ea, secret_b, secret_eb)
        ]
        plaintext = b"Educational message: Eve can decrypt and relay plain DH traffic."
        ciphertext, nonce = crypto.encrypt(ka, plaintext, b"demo")
        intercepted = crypto.decrypt(kea, ciphertext, nonce, b"demo")
        relayed, second_nonce = crypto.encrypt(keb, intercepted, b"demo")
        delivered = crypto.decrypt(kb, relayed, second_nonce, b"demo")
        self.audit.record("DEMO_PLAIN_DH_MITM", actor.id)
        return {
            "mode": "INSECURE DEMO MODE — PLAIN DH",
            "attacker_succeeded": intercepted == plaintext == delivered,
            "alice_eve_secret_matches": secret_a == secret_ea,
            "eve_bob_secret_matches": secret_b == secret_eb,
            "alice_bob_secret_matches": secret_a == secret_b,
            "mechanism": "Unauthenticated DH allows two separate attacker-controlled exchanges.",
            "explanation": intercepted.decode(),
        }

    def brute_force(self, actor) -> dict:
        auth = AuthService(self.db, self.settings, self.events, self.audit)
        statuses = []
        for _ in range(self.settings.login_failure_threshold + 1):
            try:
                auth.login(Login(username=actor.username, password=secrets.token_urlsafe(32)))
            except AppError as exc:
                statuses.append(exc.status_code)
                if exc.status_code == 429:
                    break
        return {
            "mode": "DEMO ATTACK MODE",
            "target": actor.username,
            "statuses": statuses,
            "throttled": 429 in statuses,
            "explanation": "Real password-verification failures triggered the same temporary account cooldown used by the login API.",
            "cooldown_seconds": self.settings.login_lock_seconds,
        }

    def reset_cooldown(self, actor) -> dict:
        actor.failed_login_attempts, actor.blocked_until, actor.failure_window_start = 0, 0, 0
        self.audit.record("DEMO_COOLDOWN_RESET", actor.id, "user", actor.id)
        return {"message": "Your demo account cooldown has been reset."}
