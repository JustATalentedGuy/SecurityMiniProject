import json
import time

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core import crypto
from app.core.config import Settings
from app.core.exceptions import AppError
from app.core.state_machine import transition
from app.models import SecureSession, Transfer, User
from app.repositories.repository import Repository
from app.schemas import ReceiptMetadata, SignedOperation, TransferCreate, TransferMetadata
from app.services.audit_service import AuditService
from app.services.crypto_service import CryptoService
from app.services.security_event_service import SecurityEventService
from app.services.session_service import SessionService, session_view, validated
from app.services.storage_service import StorageService


def transfer_view(transfer: Transfer, db: Session) -> dict:
    sender, receiver = db.get(User, transfer.sender_id), db.get(User, transfer.receiver_id)
    session = db.scalar(select(SecureSession).where(SecureSession.transfer_id == transfer.id))
    return {
        "id": transfer.id,
        "sender_id": transfer.sender_id,
        "receiver_id": transfer.receiver_id,
        "sender": sender.username,
        "receiver": receiver.username,
        "original_filename": transfer.original_filename,
        "safe_filename": transfer.safe_filename,
        "mime_type": transfer.mime_type,
        "file_size": transfer.file_size,
        "status": transfer.status,
        "created_at": transfer.created_at,
        "updated_at": transfer.updated_at,
        "metadata": json.loads(transfer.metadata_json) if transfer.metadata_json else None,
        "signature": transfer.signature,
        "receipt": json.loads(transfer.receipt_json) if transfer.receipt_json else None,
        "receipt_signature": transfer.receipt_signature,
        "history": json.loads(transfer.history_json),
        "session": session_view(session) if session else None,
    }


class TransferService:
    def __init__(
        self,
        db: Session,
        settings: Settings,
        storage: StorageService,
        events: SecurityEventService,
        audit: AuditService,
    ):
        self.db, self.settings, self.storage, self.events, self.audit = (
            db,
            settings,
            storage,
            events,
            audit,
        )
        self.repository = Repository(db)
        self.crypto = CryptoService(db, settings, events)
        self.sessions = SessionService(db, settings, events, audit)

    def create(self, actor: User, data: TransferCreate, idempotency_key: str) -> dict:
        request_hash = crypto.sha256(crypto.canonical(data.model_dump(mode="json")))
        existing = self.db.scalar(
            select(Transfer).where(
                Transfer.sender_id == actor.id, Transfer.idempotency_key == idempotency_key
            )
        )
        if existing:
            if existing.request_hash != request_hash:
                raise AppError(
                    "IDEMPOTENCY_CONFLICT",
                    "This idempotency key belongs to a different request.",
                    409,
                )
            return transfer_view(existing, self.db)
        if data.file_size > self.settings.max_upload_bytes:
            self.events.reject(
                "UPLOAD_LIMIT_EXCEEDED",
                "MEDIUM",
                "The selected file exceeds the configured upload limit.",
                actor.id,
                status=413,
            )
        receiver = self.repository.user(str(data.receiver_id))
        if receiver.id == actor.id:
            raise AppError("INVALID_RECEIVER", "Choose a different registered receiver.")
        transfer = Transfer(
            sender_id=actor.id,
            receiver_id=receiver.id,
            original_filename=data.original_filename,
            safe_filename=crypto.safe_filename(data.original_filename),
            mime_type=data.mime_type,
            file_size=data.file_size,
            idempotency_key=idempotency_key,
            request_hash=request_hash,
        )
        self.db.add(transfer)
        try:
            self.db.flush()
        except IntegrityError:
            self.db.rollback()
            existing = self.db.scalar(
                select(Transfer).where(
                    Transfer.sender_id == actor.id, Transfer.idempotency_key == idempotency_key
                )
            )
            if existing and existing.request_hash == request_hash:
                return transfer_view(existing, self.db)
            raise AppError(
                "IDEMPOTENCY_CONFLICT", "A concurrent request used this idempotency key.", 409
            ) from None
        transfer.history_json = json.dumps([{"status": "CREATED", "timestamp": time.time()}])
        self.audit.record("TRANSFER_CREATED", actor.id, "transfer", transfer.id)
        return transfer_view(transfer, self.db)

    def upload(
        self, actor: User, transfer_id: str, ciphertext: bytes, operation: SignedOperation
    ) -> dict:
        transfer = self.repository.transfer(transfer_id, actor)
        if transfer.sender_id != actor.id:
            raise AppError("FORBIDDEN", "Only the sender can upload this ciphertext.", 403)
        m = validated(TransferMetadata, operation.metadata)
        self.crypto.verify_signature(actor, m, operation.signature, transfer.id)
        crypto.unb64(m["nonce"], 12)
        session = self.db.scalar(
            select(SecureSession).where(SecureSession.transfer_id == transfer.id)
        )
        if not session:
            raise AppError(
                "KEY_EXCHANGE_REQUIRED", "Complete the authenticated key exchange first.", 409
            )
        self.sessions.get(session.id, actor)
        if session.status != "ESTABLISHED":
            raise AppError(
                "KEY_EXCHANGE_REQUIRED",
                "Wait for both participants to authenticate the exchange.",
                409,
            )
        expected = {
            "transfer_id": transfer.id,
            "session_identifier": session.session_identifier,
            "sender_id": transfer.sender_id,
            "receiver_id": transfer.receiver_id,
            "filename": transfer.safe_filename,
            "mime_type": transfer.mime_type,
            "file_size": transfer.file_size,
            "transcript_sha256": crypto.transcript_hash(
                json.loads(session.sender_metadata_json), json.loads(session.receiver_metadata_json)
            ),
        }
        if any(m[key] != value for key, value in expected.items()):
            raise AppError(
                "TRANSFER_CONTEXT_MISMATCH", "Signed file metadata does not match this transfer."
            )
        if len(ciphertext) > self.settings.max_upload_bytes + 16:
            self.events.reject(
                "UPLOAD_LIMIT_EXCEEDED",
                "MEDIUM",
                "Encrypted upload exceeds the size limit.",
                actor.id,
                transfer.id,
                413,
            )
        if (
            len(ciphertext) != transfer.file_size + 16
            or crypto.sha256(ciphertext) != m["ciphertext_sha256"]
        ):
            self.events.reject(
                "FILE_TAMPERING_DETECTED",
                "HIGH",
                "Uploaded ciphertext does not match the signed size and fingerprint.",
                actor.id,
                transfer.id,
            )
        self.crypto.fresh(actor.id, m["timestamp"], m["nonce"], "file-upload", transfer.id)
        self.sessions._state(transfer, "KEY_ESTABLISHED", actor)
        object_id = None
        try:
            object_id = self.storage.write(ciphertext)
            transfer.encrypted_storage_path = object_id
            transfer.metadata_json, transfer.signature = (
                crypto.canonical(m).decode(),
                operation.signature,
            )
            transfer.plaintext_sha256, transfer.ciphertext_sha256 = (
                m["plaintext_sha256"],
                m["ciphertext_sha256"],
            )
            transfer.nonce, transfer.timestamp = m["nonce"], m["timestamp"]
            for state in ("ENCRYPTED", "UPLOADED", "AVAILABLE"):
                transition(transfer, state)
            self.audit.record("SIGNATURE_VALID", actor.id, "transfer", transfer.id)
            self.audit.record("FILE_UPLOADED", actor.id, "transfer", transfer.id)
            self.db.commit()  # finalize DB here so file compensation covers commit failures
        except Exception as exc:
            self.db.rollback()
            if object_id:
                self.storage.delete(object_id)
            if isinstance(exc, OSError):
                raise AppError(
                    "STORAGE_UNAVAILABLE",
                    "Encrypted storage is unavailable. Retry the upload.",
                    503,
                ) from exc
            raise
        return transfer_view(transfer, self.db)

    def download(self, actor: User, transfer_id: str) -> bytes:
        transfer = self.repository.transfer(transfer_id, actor)
        if actor.id != transfer.receiver_id:
            raise AppError("FORBIDDEN", "Only the receiver can download this ciphertext.", 403)
        if transfer.status not in {"AVAILABLE", "DOWNLOADED", "COMPLETED"}:
            self.events.reject(
                "SUSPICIOUS_STATE_CHANGE",
                "HIGH",
                "This transfer is not available for download.",
                actor.id,
                transfer.id,
                409,
                "INVALID_STATE_TRANSITION",
            )
        session = self.db.scalar(
            select(SecureSession).where(SecureSession.transfer_id == transfer.id)
        )
        if transfer.status != "COMPLETED":
            self.sessions.get(session.id, actor)
        sender = self.repository.user(transfer.sender_id)
        if not crypto.verify(
            sender.public_key_pem,
            transfer.signature,
            crypto.canonical(json.loads(transfer.metadata_json)),
        ):
            if transfer.status != "COMPLETED":
                transition(transfer, "SIGNATURE_INVALID")
            self.events.reject(
                "SIGNATURE_INVALID",
                "HIGH",
                "The stored sender signature is invalid. File rejected.",
                actor.id,
                transfer.id,
                code="SIGNATURE_VERIFICATION_FAILED",
            )
        ciphertext = self.storage.read(transfer.encrypted_storage_path)
        if crypto.sha256(ciphertext) != transfer.ciphertext_sha256:
            if transfer.status != "COMPLETED":
                transition(transfer, "TAMPERED")
            self.events.reject(
                "FILE_TAMPERING_DETECTED",
                "HIGH",
                "Encrypted file fingerprint mismatch. File rejected.",
                actor.id,
                transfer.id,
            )
        if transfer.status == "AVAILABLE":
            transition(transfer, "DOWNLOADED")
        self.audit.record("FILE_DOWNLOADED", actor.id, "transfer", transfer.id)
        return ciphertext

    def verify(self, actor: User, transfer_id: str, operation: SignedOperation) -> dict:
        transfer = self.repository.transfer(transfer_id, actor)
        if actor.id != transfer.receiver_id:
            raise AppError("FORBIDDEN", "Only the receiver can submit a verification receipt.", 403)
        m = validated(ReceiptMetadata, operation.metadata)
        self.crypto.verify_signature(actor, m, operation.signature, transfer.id)
        if m["transfer_id"] != transfer.id or m["receiver_id"] != actor.id:
            raise AppError(
                "RECEIPT_CONTEXT_MISMATCH", "Receipt belongs to a different transfer or receiver."
            )
        self.crypto.fresh(actor.id, m["timestamp"], m["nonce"], "transfer-receipt", transfer.id)
        if m["result"] == "VERIFIED" or transfer.status != "AVAILABLE":
            self.sessions._state(transfer, "DOWNLOADED", actor)
        if m["result"] == "VERIFIED":
            session = self.db.scalar(
                select(SecureSession).where(SecureSession.transfer_id == transfer.id)
            )
            self.sessions.get(session.id, actor)
        if m["result"] == "VERIFIED" and m["plaintext_sha256"] != transfer.plaintext_sha256:
            transition(transfer, "TAMPERED")
            self.events.reject(
                "FILE_TAMPERING_DETECTED",
                "HIGH",
                "Recipient fingerprint does not match the sender's signed fingerprint.",
                actor.id,
                transfer.id,
            )
        transfer.receipt_json, transfer.receipt_signature = (
            crypto.canonical(m).decode(),
            operation.signature,
        )
        if m["result"] == "VERIFIED":
            transition(transfer, "VERIFIED")
            transition(transfer, "COMPLETED")
            self.audit.record("FILE_INTEGRITY_VALID", actor.id, "transfer", transfer.id)
        else:
            transition(transfer, m["result"])
            self.events.record(
                "SIGNATURE_INVALID"
                if m["result"] == "SIGNATURE_INVALID"
                else "CLIENT_VERIFICATION_FAILED"
                if m["result"] == "FAILED"
                else "FILE_TAMPERING_DETECTED",
                "HIGH",
                "Recipient rejected the transfer during local cryptographic verification.",
                actor.id,
                transfer.id,
            )
        return transfer_view(transfer, self.db)

    def list(self, actor: User, received: bool) -> list[dict]:
        column = Transfer.receiver_id if received else Transfer.sender_id
        return [
            transfer_view(transfer, self.db)
            for transfer in self.db.scalars(
                select(Transfer)
                .where(column == actor.id)
                .order_by(Transfer.created_at.desc())
                .limit(200)
            )
        ]

    def detail(self, actor: User, transfer_id: str) -> dict:
        return transfer_view(self.repository.transfer(transfer_id, actor), self.db)

    def stats(self, actor: User) -> dict:
        counts = dict(
            self.db.execute(
                select(Transfer.status, func.count())
                .where((Transfer.sender_id == actor.id) | (Transfer.receiver_id == actor.id))
                .group_by(Transfer.status)
            ).all()
        )
        sent = self.db.scalar(
            select(func.count()).select_from(Transfer).where(Transfer.sender_id == actor.id)
        )
        received = self.db.scalar(
            select(func.count()).select_from(Transfer).where(Transfer.receiver_id == actor.id)
        )
        terminal = {
            "COMPLETED",
            "REJECTED",
            "TAMPERED",
            "SIGNATURE_INVALID",
            "REPLAY_REJECTED",
            "FAILED",
        }
        return {
            "sent": sent,
            "received": received,
            "completed": counts.get("COMPLETED", 0),
            "pending": sum(count for state, count in counts.items() if state not in terminal),
            "by_status": counts,
        }
