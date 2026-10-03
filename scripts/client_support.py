"""Local client utilities shared by demo setup and validation (never a server route)."""

import base64
import json
import secrets
import sys
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
from app.core import crypto  # noqa: E402


def seal_vault(vault: dict, password: str) -> dict:
    salt, nonce = secrets.token_bytes(16), secrets.token_bytes(12)
    key = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=600000).derive(
        password.encode()
    )
    ciphertext = AESGCM(key).encrypt(nonce, json.dumps(vault).encode(), b"secureshare-x/vault/v1")
    return {
        "version": 1,
        "username": vault["username"],
        "kdf": {
            "name": "PBKDF2-SHA256",
            "iterations": 600000,
            "salt": crypto.b64(salt),
        },
        "nonce": crypto.b64(nonce),
        "ciphertext": crypto.b64(ciphertext),
    }


def open_vault(envelope: dict, password: str) -> dict:
    if envelope["version"] != 1 or envelope["kdf"]["iterations"] != 600000:
        raise ValueError("Unsupported vault")
    key = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=crypto.unb64(envelope["kdf"]["salt"], 16),
        iterations=600000,
    ).derive(password.encode())
    return json.loads(
        AESGCM(key).decrypt(
            crypto.unb64(envelope["nonce"], 12),
            crypto.unb64(envelope["ciphertext"]),
            b"secureshare-x/vault/v1",
        )
    )


def vault_for_key(username: str, key) -> dict:
    return {
        "version": 1,
        "username": username,
        "identityPrivate": base64.b64encode(
            key.private_bytes(
                serialization.Encoding.DER,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        ).decode(),
        "publicKeyPem": crypto.public_pem(key.public_key()),
        "sessions": {},
        "pins": {},
    }
