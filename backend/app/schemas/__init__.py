from typing import Annotated, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

Username = Annotated[str, Field(pattern=r"^[a-zA-Z][a-zA-Z0-9_-]{2,31}$")]
Nonce = Annotated[str, Field(pattern=r"^[a-f0-9]{32}$")]
Hash = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=False)


class Login(StrictModel):
    username: Username
    password: str = Field(min_length=1, max_length=128)


class Register(Login):
    password: str = Field(min_length=10, max_length=128)
    public_key_pem: str = Field(min_length=100, max_length=2000)


class ChallengeRequest(StrictModel):
    username: Username


class ChallengeVerify(StrictModel):
    challenge_id: UUID
    signature: str = Field(min_length=100, max_length=800)


class TransferCreate(StrictModel):
    receiver_id: UUID
    original_filename: str = Field(min_length=1, max_length=255)
    mime_type: str = Field(
        default="application/octet-stream",
        pattern=r"^[a-zA-Z0-9.+_-]+/[a-zA-Z0-9.+_-]+$",
        max_length=100,
    )
    file_size: int = Field(ge=0, strict=True)

    @field_validator("original_filename")
    @classmethod
    def no_controls(cls, value: str) -> str:
        if any(ord(char) < 32 or ord(char) == 127 for char in value):
            raise ValueError("Filename must not contain control characters")
        return value


class SignedOperation(StrictModel):
    metadata: dict
    signature: str = Field(min_length=100, max_length=800)


class DHMetadata(StrictModel):
    protocol: Literal["secureshare-x/v1"]
    purpose: Literal["dh-initiate", "dh-respond"]
    transfer_id: UUID
    session_identifier: UUID
    sender_id: UUID
    receiver_id: UUID
    sender_ephemeral_public_key: str = Field(min_length=44, max_length=44)
    receiver_ephemeral_public_key: str | None = Field(default=None, min_length=44, max_length=44)
    timestamp: int = Field(strict=True)
    nonce: Nonce


class ConfirmMetadata(StrictModel):
    protocol: Literal["secureshare-x/v1"]
    purpose: Literal["dh-confirm"]
    transfer_id: UUID
    session_identifier: UUID
    transcript_sha256: Hash
    timestamp: int = Field(strict=True)
    nonce: Nonce


class TransferMetadata(StrictModel):
    protocol: Literal["secureshare-x/v1"]
    purpose: Literal["file-transfer"]
    transfer_id: UUID
    session_identifier: UUID
    sender_id: UUID
    receiver_id: UUID
    filename: str = Field(min_length=1, max_length=255)
    mime_type: str = Field(max_length=100)
    file_size: int = Field(ge=0, strict=True)
    plaintext_sha256: Hash
    ciphertext_sha256: Hash
    transcript_sha256: Hash
    nonce: str = Field(min_length=16, max_length=16)
    timestamp: int = Field(strict=True)


class ReceiptMetadata(StrictModel):
    protocol: Literal["secureshare-x/v1"]
    purpose: Literal["transfer-receipt"]
    transfer_id: UUID
    receiver_id: UUID
    result: Literal["VERIFIED", "TAMPERED", "SIGNATURE_INVALID", "FAILED"]
    plaintext_sha256: Hash | None = None
    timestamp: int = Field(strict=True)
    nonce: Nonce
