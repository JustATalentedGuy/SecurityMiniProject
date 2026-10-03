import time

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core import crypto
from app.core.config import Settings
from app.models import ConsumedNonce, User
from app.services.security_event_service import SecurityEventService


class CryptoService:
    def __init__(self, db: Session, settings: Settings, events: SecurityEventService):
        self.db, self.settings, self.events = db, settings, events

    def verify_signature(
        self,
        user: User,
        metadata: dict,
        signature: str,
        transfer_id: str | None = None,
        mitm: bool = False,
    ) -> None:
        if not crypto.verify(user.public_key_pem, signature, crypto.canonical(metadata)):
            self.events.reject(
                "MITM_DETECTED" if mitm else "SIGNATURE_INVALID",
                "CRITICAL" if mitm else "HIGH",
                "The supplied digital signature could not be verified.",
                user.id,
                transfer_id,
                code="SIGNATURE_VERIFICATION_FAILED",
            )

    def fresh(
        self, user_id: str, timestamp: int, nonce: str, purpose: str, transfer_id: str | None = None
    ) -> None:
        if abs(time.time() - timestamp) > self.settings.replay_window_seconds:
            self.events.reject(
                "REPLAY_ATTACK",
                "HIGH",
                "The signed timestamp is outside the allowed replay window.",
                user_id,
                transfer_id,
                code="TIMESTAMP_EXPIRED",
            )
        existing = self.db.scalar(
            select(ConsumedNonce).where(
                ConsumedNonce.user_id == user_id, ConsumedNonce.nonce == nonce
            )
        )
        if existing:
            self.events.reject(
                "REPLAY_ATTACK",
                "HIGH",
                "This nonce has already been consumed; request rejected.",
                user_id,
                transfer_id,
                409,
                "REPLAY_ATTACK_DETECTED",
            )
        self.db.add(
            ConsumedNonce(user_id=user_id, nonce=nonce, transfer_id=transfer_id, purpose=purpose)
        )
        self.db.flush()  # unique constraint closes concurrent replay races
