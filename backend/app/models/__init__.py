"""Database records. No private key, session secret, or plaintext content columns."""

import time
import uuid

from sqlalchemy import Boolean, Float, ForeignKey, Integer, String, Text, UniqueConstraint, event
from sqlalchemy.orm import Mapped, mapped_column

from app.db.database import Base


def identifier() -> str:
    return str(uuid.uuid4())


class User(Base):
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=identifier)
    username: Mapped[str] = mapped_column(String(32), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(Text)
    public_key_pem: Mapped[str] = mapped_column(Text)
    created_at: Mapped[float] = mapped_column(Float, default=time.time)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    failed_login_attempts: Mapped[int] = mapped_column(Integer, default=0)
    failure_window_start: Mapped[float] = mapped_column(Float, default=0)
    blocked_until: Mapped[float] = mapped_column(Float, default=0)


class AuthToken(Base):
    __tablename__ = "auth_tokens"
    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    expires_at: Mapped[float] = mapped_column(Float)


class AuthChallenge(Base):
    __tablename__ = "auth_challenges"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=identifier)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    challenge: Mapped[str] = mapped_column(String(128))
    expires_at: Mapped[float] = mapped_column(Float)
    used: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[float] = mapped_column(Float, default=time.time)


class SecureSession(Base):
    __tablename__ = "secure_sessions"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=identifier)
    transfer_id: Mapped[str] = mapped_column(ForeignKey("transfers.id"), unique=True)
    sender_id: Mapped[str] = mapped_column(ForeignKey("users.id"))
    receiver_id: Mapped[str] = mapped_column(ForeignKey("users.id"))
    session_identifier: Mapped[str] = mapped_column(String(36), unique=True)
    sender_ephemeral_public_key: Mapped[str] = mapped_column(String(44))
    receiver_ephemeral_public_key: Mapped[str | None] = mapped_column(String(44), nullable=True)
    sender_metadata_json: Mapped[str] = mapped_column(Text)
    receiver_metadata_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    sender_signature: Mapped[str] = mapped_column(Text)
    receiver_signature: Mapped[str | None] = mapped_column(Text, nullable=True)
    confirmation_metadata_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    confirmation_signature: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(24), default="PENDING")
    created_at: Mapped[float] = mapped_column(Float, default=time.time)
    expires_at: Mapped[float] = mapped_column(Float)


class Transfer(Base):
    __tablename__ = "transfers"
    __table_args__ = (UniqueConstraint("sender_id", "idempotency_key"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=identifier)
    sender_id: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    receiver_id: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    original_filename: Mapped[str] = mapped_column(String(255))
    safe_filename: Mapped[str] = mapped_column(String(255))
    mime_type: Mapped[str] = mapped_column(String(100))
    encrypted_storage_path: Mapped[str | None] = mapped_column(String(64), nullable=True)
    file_size: Mapped[int] = mapped_column(Integer)
    plaintext_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    ciphertext_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    signature: Mapped[str | None] = mapped_column(Text, nullable=True)
    nonce: Mapped[str | None] = mapped_column(String(44), nullable=True)
    timestamp: Mapped[int | None] = mapped_column(Integer, nullable=True)
    metadata_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    receipt_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    receipt_signature: Mapped[str | None] = mapped_column(Text, nullable=True)
    idempotency_key: Mapped[str] = mapped_column(String(36))
    request_hash: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(32), default="CREATED")
    history_json: Mapped[str] = mapped_column(Text, default="[]")
    created_at: Mapped[float] = mapped_column(Float, default=time.time)
    updated_at: Mapped[float] = mapped_column(Float, default=time.time)


class ConsumedNonce(Base):
    __tablename__ = "consumed_nonces"
    __table_args__ = (UniqueConstraint("user_id", "nonce"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    nonce: Mapped[str] = mapped_column(String(128))
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    transfer_id: Mapped[str | None] = mapped_column(ForeignKey("transfers.id"), nullable=True)
    purpose: Mapped[str] = mapped_column(String(32))
    created_at: Mapped[float] = mapped_column(Float, default=time.time)


class SecurityEvent(Base):
    __tablename__ = "security_events"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    event_type: Mapped[str] = mapped_column(String(64), index=True)
    severity: Mapped[str] = mapped_column(String(12))
    user_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    transfer_id: Mapped[str | None] = mapped_column(ForeignKey("transfers.id"), nullable=True)
    source_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    description: Mapped[str] = mapped_column(Text)
    metadata_json: Mapped[str] = mapped_column(Text, default="{}")
    request_id: Mapped[str] = mapped_column(String(36))
    created_at: Mapped[float] = mapped_column(Float, default=time.time)


class AuditLog(Base):
    __tablename__ = "audit_logs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    actor_user_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    action: Mapped[str] = mapped_column(String(64))
    resource_type: Mapped[str] = mapped_column(String(32))
    resource_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    request_id: Mapped[str] = mapped_column(String(36))
    created_at: Mapped[float] = mapped_column(Float, default=time.time)


@event.listens_for(AuditLog, "before_update")
@event.listens_for(AuditLog, "before_delete")
def immutable_audit(_mapper, _connection, _target):
    raise ValueError("Audit records are append-only through the application.")
