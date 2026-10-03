"""Protocol v1 primitives; the server never derives real users' shared keys."""

import base64
import hashlib
import json
import re
import secrets

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from app.core.exceptions import AppError

PROTOCOL = "secureshare-x/v1"


def canonical(data: dict) -> bytes:
    """Sorted compact ASCII JSON, integer timestamps, no floats in signed objects."""
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def unb64(value: str, length: int | None = None) -> bytes:
    try:
        decoded = base64.b64decode(value, validate=True)
        if length is not None and len(decoded) != length:
            raise ValueError("length")
        if b64(decoded) != value:
            raise ValueError("noncanonical base64")
        return decoded
    except (ValueError, TypeError) as exc:
        raise AppError("INVALID_CRYPTO_PARAMETER", "Invalid cryptographic parameter.") from exc


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_public_key(pem: str) -> rsa.RSAPublicKey:
    try:
        key = serialization.load_pem_public_key(pem.encode("ascii"))
        if not isinstance(key, rsa.RSAPublicKey) or not 2048 <= key.key_size <= 4096:
            raise ValueError("RSA key size")
        if key.public_numbers().e != 65537:
            raise ValueError("RSA exponent")
        return key
    except (ValueError, TypeError, UnicodeError) as exc:
        raise AppError(
            "MALFORMED_PUBLIC_KEY", "Provide an RSA public key of 2048–4096 bits."
        ) from exc


def public_pem(key: rsa.RSAPublicKey) -> str:
    return key.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()


def fingerprint(pem: str) -> str:
    key = load_public_key(pem)
    return sha256(
        key.public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )


def sign(key: rsa.RSAPrivateKey, data: bytes) -> str:
    return b64(
        key.sign(
            data, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32), hashes.SHA256()
        )
    )


def verify(pem: str, signature: str, data: bytes) -> bool:
    try:
        load_public_key(pem).verify(
            unb64(signature),
            data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
            hashes.SHA256(),
        )
        return True
    except (InvalidSignature, AppError, ValueError):
        return False


def validate_x25519(value: str) -> None:
    try:
        peer = x25519.X25519PublicKey.from_public_bytes(unb64(value, 32))
        x25519.X25519PrivateKey.generate().exchange(peer)  # reject low-order points
    except ValueError as exc:
        raise AppError("INVALID_DH_KEY", "The X25519 public value is invalid.") from exc


def transcript_hash(sender: dict, receiver: dict) -> str:
    return sha256(canonical({"sender": sender, "receiver": receiver}))


def derive_key(secret: bytes, session_identifier: str, transcript: str) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=bytes.fromhex(transcript),
        info=f"{PROTOCOL}/aes256gcm/{session_identifier}".encode(),
    ).derive(secret)


def encrypt(key: bytes, plaintext: bytes, aad: bytes) -> tuple[bytes, str]:
    nonce = secrets.token_bytes(12)
    return AESGCM(key).encrypt(nonce, plaintext, aad), b64(nonce)


def decrypt(key: bytes, ciphertext: bytes, nonce: str, aad: bytes) -> bytes:
    return AESGCM(key).decrypt(unb64(nonce, 12), ciphertext, aad)


def safe_filename(filename: str) -> str:
    # Basename is display metadata only; storage uses server-generated UUIDs.
    name = filename.replace("\\", "/").split("/")[-1]
    name = re.sub(r"[^A-Za-z0-9._ -]", "_", name).strip(" .")[:200]
    if not name or name.upper().split(".")[0] in {
        "CON",
        "PRN",
        "AUX",
        "NUL",
        *(f"COM{i}" for i in range(1, 10)),
        *(f"LPT{i}" for i in range(1, 10)),
    }:
        return "document.bin"
    return name
