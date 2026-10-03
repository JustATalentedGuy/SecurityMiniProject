import json
import time

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core import crypto
from app.core.config import Settings
from app.core.exceptions import AppError
from app.core.state_machine import transition
from app.models import SecureSession, Transfer, User
from app.repositories.repository import Repository
from app.schemas import ConfirmMetadata, DHMetadata, SignedOperation
from app.services.audit_service import AuditService
from app.services.crypto_service import CryptoService
from app.services.security_event_service import SecurityEventService


def validated(schema, metadata: dict) -> dict:
    value = schema.model_validate(metadata).model_dump(mode="json")
    if value != metadata:
        raise AppError(
            "NONCANONICAL_METADATA",
            "Signed metadata must include the complete canonical protocol fields.",
        )
    return value


def session_view(session: SecureSession) -> dict:
    return {
        "id": session.id,
        "transfer_id": session.transfer_id,
        "session_identifier": session.session_identifier,
        "sender_id": session.sender_id,
        "receiver_id": session.receiver_id,
        "status": session.status,
        "created_at": session.created_at,
        "expires_at": session.expires_at,
        "sender_metadata": json.loads(session.sender_metadata_json),
        "receiver_metadata": json.loads(session.receiver_metadata_json)
        if session.receiver_metadata_json
        else None,
        "sender_signature": session.sender_signature,
        "receiver_signature": session.receiver_signature,
        "confirmation_metadata": json.loads(session.confirmation_metadata_json)
        if session.confirmation_metadata_json
        else None,
        "confirmation_signature": session.confirmation_signature,
    }


class SessionService:
    def __init__(
        self, db: Session, settings: Settings, events: SecurityEventService, audit: AuditService
    ):
        self.db, self.settings, self.events, self.audit = db, settings, events, audit
        self.repository = Repository(db)
        self.crypto = CryptoService(db, settings, events)

    def _state(self, transfer: Transfer, expected: str, actor: User) -> None:
        if transfer.status != expected:
            self.events.reject(
                "SUSPICIOUS_STATE_CHANGE",
                "HIGH",
                f"Operation requires {expected}; transfer is {transfer.status}.",
                actor.id,
                transfer.id,
                409,
                "INVALID_STATE_TRANSITION",
            )

    def get(self, session_id: str, actor: User) -> tuple[SecureSession, Transfer]:
        session = self.db.get(SecureSession, session_id)
        if not session or actor.id not in (session.sender_id, session.receiver_id):
            raise AppError("SESSION_NOT_FOUND", "Secure session not found or inaccessible.", 404)
        if session.expires_at <= time.time():
            self.events.reject(
                "SESSION_EXPIRED",
                "MEDIUM",
                "Secure session expired. Create a new transfer.",
                actor.id,
                session.transfer_id,
                409,
            )
        return session, self.repository.transfer(session.transfer_id, actor)

    def initiate(self, actor: User, operation: SignedOperation) -> dict:
        m = validated(DHMetadata, operation.metadata)
        transfer = self.repository.transfer(m["transfer_id"], actor)
        if (
            transfer.sender_id != actor.id
            or m["sender_id"] != actor.id
            or m["receiver_id"] != transfer.receiver_id
            or m["purpose"] != "dh-initiate"
            or m["receiver_ephemeral_public_key"] is not None
        ):
            raise AppError("SESSION_CONTEXT_MISMATCH", "Key exchange does not match this transfer.")
        self.crypto.verify_signature(actor, m, operation.signature, transfer.id, mitm=True)
        crypto.validate_x25519(m["sender_ephemeral_public_key"])
        self.crypto.fresh(actor.id, m["timestamp"], m["nonce"], "dh-initiate", transfer.id)
        self._state(transfer, "CREATED", actor)
        session = SecureSession(
            transfer_id=transfer.id,
            sender_id=actor.id,
            receiver_id=transfer.receiver_id,
            session_identifier=m["session_identifier"],
            sender_ephemeral_public_key=m["sender_ephemeral_public_key"],
            sender_metadata_json=crypto.canonical(m).decode(),
            sender_signature=operation.signature,
            expires_at=time.time() + self.settings.session_expiry_minutes * 60,
        )
        self.db.add(session)
        self.db.flush()
        transition(transfer, "KEY_EXCHANGE_PENDING")
        self.audit.record("DH_INITIATED", actor.id, "transfer", transfer.id)
        return session_view(session)

    def respond(self, session_id: str, actor: User, operation: SignedOperation) -> dict:
        session, transfer = self.get(session_id, actor)
        if actor.id != session.receiver_id:
            raise AppError("FORBIDDEN", "Only the receiver can respond to this exchange.", 403)
        m = validated(DHMetadata, operation.metadata)
        expected = {
            "sender_id": session.sender_id,
            "receiver_id": session.receiver_id,
            "transfer_id": transfer.id,
            "session_identifier": session.session_identifier,
            "sender_ephemeral_public_key": session.sender_ephemeral_public_key,
            "purpose": "dh-respond",
        }
        if (
            any(m[key] != value for key, value in expected.items())
            or not m["receiver_ephemeral_public_key"]
        ):
            raise AppError(
                "SESSION_CONTEXT_MISMATCH",
                "Receiver response does not bind the original signed exchange.",
            )
        self.crypto.verify_signature(
            self.repository.user(session.sender_id),
            json.loads(session.sender_metadata_json),
            session.sender_signature,
            transfer.id,
            mitm=True,
        )
        self.crypto.verify_signature(actor, m, operation.signature, transfer.id, mitm=True)
        crypto.validate_x25519(m["receiver_ephemeral_public_key"])
        self.crypto.fresh(actor.id, m["timestamp"], m["nonce"], "dh-respond", transfer.id)
        self._state(transfer, "KEY_EXCHANGE_PENDING", actor)
        if session.status != "PENDING":
            raise AppError(
                "INVALID_SESSION_STATE", "This key exchange already has a response.", 409
            )
        session.receiver_ephemeral_public_key = m["receiver_ephemeral_public_key"]
        session.receiver_metadata_json = crypto.canonical(m).decode()
        session.receiver_signature = operation.signature
        session.status = "RESPONDED"
        self.audit.record("DH_RESPONDED", actor.id, "transfer", transfer.id)
        return session_view(session)

    def verify(self, session_id: str, actor: User, operation: SignedOperation) -> dict:
        session, transfer = self.get(session_id, actor)
        if actor.id != session.sender_id:
            raise AppError("FORBIDDEN", "Only the sender can confirm this exchange.", 403)
        m = validated(ConfirmMetadata, operation.metadata)
        self.crypto.verify_signature(actor, m, operation.signature, transfer.id)
        self.crypto.fresh(actor.id, m["timestamp"], m["nonce"], "dh-confirm", transfer.id)
        self._state(transfer, "KEY_EXCHANGE_PENDING", actor)
        if session.status != "RESPONDED":
            raise AppError("INVALID_SESSION_STATE", "Wait for the receiver's signed response.", 409)
        transcript = crypto.transcript_hash(
            json.loads(session.sender_metadata_json), json.loads(session.receiver_metadata_json)
        )
        if (
            m["transfer_id"] != transfer.id
            or m["session_identifier"] != session.session_identifier
            or m["transcript_sha256"] != transcript
        ):
            self.events.reject(
                "MITM_DETECTED",
                "CRITICAL",
                "Key exchange transcript does not match the signed participants.",
                actor.id,
                transfer.id,
            )
        self.crypto.verify_signature(
            self.repository.user(session.receiver_id),
            json.loads(session.receiver_metadata_json),
            session.receiver_signature,
            transfer.id,
            mitm=True,
        )
        session.confirmation_metadata_json = crypto.canonical(m).decode()
        session.confirmation_signature = operation.signature
        session.status = "ESTABLISHED"
        transition(transfer, "KEY_ESTABLISHED")
        self.audit.record("DH_VERIFIED", actor.id, "transfer", transfer.id)
        return session_view(session)

    def list(self, actor: User) -> list[dict]:
        sessions = self.db.scalars(
            select(SecureSession)
            .where((SecureSession.sender_id == actor.id) | (SecureSession.receiver_id == actor.id))
            .order_by(SecureSession.created_at.desc())
        )
        return [session_view(session) for session in sessions]
