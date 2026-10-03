import os
import re
import secrets
from pathlib import Path
from typing import Protocol

from app.core.exceptions import AppError


class StorageService(Protocol):
    def write(self, ciphertext: bytes) -> str: ...
    def read(self, object_id: str) -> bytes: ...
    def delete(self, object_id: str) -> None: ...
    def healthy(self) -> bool: ...


class LocalEncryptedStorage:
    def __init__(self, root: Path):
        self.root = root.resolve()
        self.root.mkdir(parents=True, exist_ok=True)

    def _path(self, object_id: str) -> Path:
        if not re.fullmatch(r"[a-f0-9]{32}\.enc", object_id):
            raise AppError("UNSAFE_STORAGE_PATH", "Invalid encrypted object identifier.")
        path = (self.root / object_id).resolve()
        if path.parent != self.root:
            raise AppError("UNSAFE_STORAGE_PATH", "Encrypted object is outside storage.")
        return path

    def write(self, ciphertext: bytes) -> str:
        object_id = secrets.token_hex(16) + ".enc"
        destination = self._path(object_id)
        temporary = destination.with_suffix(".tmp")
        try:
            with temporary.open("xb") as handle:
                handle.write(ciphertext)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, destination)
        finally:
            temporary.unlink(missing_ok=True)
        return object_id

    def read(self, object_id: str) -> bytes:
        try:
            return self._path(object_id).read_bytes()
        except FileNotFoundError as exc:
            raise AppError(
                "ENCRYPTED_FILE_MISSING", "The encrypted file is unavailable.", 404
            ) from exc

    def delete(self, object_id: str) -> None:
        self._path(object_id).unlink(missing_ok=True)

    def healthy(self) -> bool:
        return self.root.is_dir() and os.access(self.root, os.R_OK | os.W_OK)
