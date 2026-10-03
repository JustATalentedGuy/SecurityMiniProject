import time
import uuid

import pytest
from app.core import crypto
from app.models import ConsumedNonce, SecureSession, Transfer
from sqlalchemy import select

from tests.helpers import establish, package, receipt, request, signed, upload


def test_complete_authenticated_transfer(client, identities, app):
    exchange = establish(client, identities)
    metadata, ciphertext = package(exchange)
    response = upload(client, identities, exchange, metadata, ciphertext)
    assert response.status_code == 200, response.text
    transfer_id = exchange["transfer"]["id"]
    assert response.json()["status"] == "AVAILABLE"
    downloaded = request(client, "get", f"/transfers/{transfer_id}/download", identities["bob"])
    assert downloaded.status_code == 200
    aad = {key: value for key, value in metadata.items() if key != "ciphertext_sha256"}
    plaintext = crypto.decrypt(
        exchange["key"], downloaded.content, metadata["nonce"], crypto.canonical(aad)
    )
    assert plaintext == exchange["content"]
    data = signed(identities["bob"], receipt(exchange, identities))
    completed = request(
        client, "post", f"/transfers/{transfer_id}/verify", identities["bob"], json=data
    )
    assert completed.status_code == 200, completed.text
    assert completed.json()["status"] == "COMPLETED"
    assert [step["status"] for step in completed.json()["history"]] == [
        "CREATED",
        "KEY_EXCHANGE_PENDING",
        "KEY_ESTABLISHED",
        "ENCRYPTED",
        "UPLOADED",
        "AVAILABLE",
        "DOWNLOADED",
        "VERIFIED",
        "COMPLETED",
    ]
    repeated = request(
        client, "post", f"/transfers/{transfer_id}/verify", identities["bob"], json=data
    )
    assert repeated.status_code == 409
    assert repeated.json()["error"] == "REPLAY_ATTACK_DETECTED"
    # Repeat downloads are safe and don't create another verification receipt.
    assert (
        request(client, "get", f"/transfers/{transfer_id}/download", identities["bob"]).content
        == ciphertext
    )
    with app.state.database() as db:
        transfer = db.get(Transfer, transfer_id)
        stored = app.state.storage.read(transfer.encrypted_storage_path)
        assert exchange["content"] not in stored
        assert stored == ciphertext


@pytest.mark.parametrize(
    ("action", "error", "state"),
    [
        ("tamper", "FILE_TAMPERING_DETECTED", "TAMPERED"),
        ("signature", "SIGNATURE_VERIFICATION_FAILED", "SIGNATURE_INVALID"),
    ],
)
def test_attack_rejection(client, identities, action, error, state):
    exchange = establish(client, identities)
    assert upload(client, identities, exchange).status_code == 200
    transfer_id = exchange["transfer"]["id"]
    assert (
        request(
            client, "post", f"/demo/transfers/{transfer_id}/{action}", identities["alice"]
        ).status_code
        == 200
    )
    download = request(client, "get", f"/transfers/{transfer_id}/download", identities["bob"])
    assert download.status_code == 400
    assert download.json()["error"] == error
    assert (
        request(client, "get", f"/transfers/{transfer_id}", identities["bob"]).json()["status"]
        == state
    )
    events = request(client, "get", "/security/events", identities["bob"]).json()
    assert any(
        event["severity"] == "HIGH" and event["transfer_id"] == transfer_id for event in events
    )


def test_upload_signature_and_ciphertext_mutations(client, identities):
    exchange = establish(client, identities)
    metadata, ciphertext = package(exchange)
    response = upload(
        client,
        identities,
        exchange,
        metadata,
        ciphertext,
        signed(identities["eve"], metadata)["signature"],
    )
    assert response.json()["error"] == "SIGNATURE_VERIFICATION_FAILED"
    altered = bytes([ciphertext[0] ^ 1]) + ciphertext[1:]
    response = upload(client, identities, exchange, metadata, altered)
    assert response.json()["error"] == "FILE_TAMPERING_DETECTED"
    assert upload(client, identities, exchange, metadata, ciphertext).status_code == 200
    repeated = upload(client, identities, exchange, metadata, ciphertext)
    assert repeated.status_code == 409
    assert repeated.json()["error"] == "REPLAY_ATTACK_DETECTED"


def test_expired_upload_timestamp_and_context_binding(client, identities):
    exchange = establish(client, identities)
    metadata, ciphertext = package(exchange)
    metadata["timestamp"] -= 1000
    assert (
        upload(client, identities, exchange, metadata, ciphertext).json()["error"]
        == "TIMESTAMP_EXPIRED"
    )
    metadata["timestamp"] = int(time.time())
    metadata["receiver_id"] = identities["eve"]["user"]["id"]
    assert (
        upload(client, identities, exchange, metadata, ciphertext).json()["error"]
        == "TRANSFER_CONTEXT_MISMATCH"
    )


def test_idempotency_reuses_transfer_and_detects_conflict(client, identities):
    alice, bob = identities["alice"], identities["bob"]
    headers = {"Idempotency-Key": str(uuid.uuid4())}
    data = {"receiver_id": bob["user"]["id"], "original_filename": "file.txt", "file_size": 3}
    first = request(client, "post", "/transfers", alice, headers=headers, json=data)
    second = request(client, "post", "/transfers", alice, headers=headers, json=data)
    assert first.status_code == second.status_code == 201
    assert first.json()["id"] == second.json()["id"]
    assert len(request(client, "get", "/transfers/sent", alice).json()) == 1
    data["file_size"] = 4
    assert (
        request(client, "post", "/transfers", alice, headers=headers, json=data).json()["error"]
        == "IDEMPOTENCY_CONFLICT"
    )
    assert request(client, "post", "/transfers", alice, json=data).status_code == 422


def test_authorization_and_visibility(client, identities):
    exchange = establish(client, identities)
    assert upload(client, identities, exchange).status_code == 200
    transfer_id = exchange["transfer"]["id"]
    for path in (
        f"/transfers/{transfer_id}",
        f"/transfers/{transfer_id}/download",
        f"/sessions/{exchange['session_id']}",
    ):
        assert request(client, "get", path, identities["eve"]).status_code == 404
    assert (
        request(
            client, "post", f"/demo/transfers/{transfer_id}/tamper", identities["eve"]
        ).status_code
        == 404
    )
    assert (
        request(
            client, "get", f"/transfers/{transfer_id}/download", identities["alice"]
        ).status_code
        == 403
    )
    assert request(client, "get", "/transfers/received", identities["eve"]).json() == []
    assert all(
        event["transfer_id"] != transfer_id
        for event in request(client, "get", "/security/events", identities["eve"]).json()
    )


def test_invalid_transition_is_detected(client, identities):
    exchange = establish(client, identities)
    response = request(
        client,
        "post",
        f"/transfers/{exchange['transfer']['id']}/verify",
        identities["bob"],
        json=signed(identities["bob"], receipt(exchange, identities)),
    )
    assert response.status_code == 409
    assert response.json()["error"] == "INVALID_STATE_TRANSITION"
    assert any(
        event["event_type"] == "SUSPICIOUS_STATE_CHANGE"
        for event in request(client, "get", "/security/events", identities["bob"]).json()
    )


def test_receipt_hash_mismatch_rejects_transfer(client, identities):
    exchange = establish(client, identities)
    assert upload(client, identities, exchange).status_code == 200
    transfer_id = exchange["transfer"]["id"]
    assert (
        request(client, "get", f"/transfers/{transfer_id}/download", identities["bob"]).status_code
        == 200
    )
    metadata = receipt(exchange, identities, file_hash="0" * 64)
    response = request(
        client,
        "post",
        f"/transfers/{transfer_id}/verify",
        identities["bob"],
        json=signed(identities["bob"], metadata),
    )
    assert response.json()["error"] == "FILE_TAMPERING_DETECTED"
    assert (
        request(client, "get", f"/transfers/{transfer_id}", identities["bob"]).json()["status"]
        == "TAMPERED"
    )


def test_expired_session_and_missing_encrypted_file(client, identities, app):
    exchange = establish(client, identities)
    assert upload(client, identities, exchange).status_code == 200
    transfer_id = exchange["transfer"]["id"]
    with app.state.database() as db:
        session = db.get(SecureSession, exchange["session_id"])
        session.expires_at = time.time() - 1
        db.commit()
    assert (
        request(client, "get", f"/transfers/{transfer_id}/download", identities["bob"]).json()[
            "error"
        ]
        == "SESSION_EXPIRED"
    )
    with app.state.database() as db:
        db.get(SecureSession, exchange["session_id"]).expires_at = time.time() + 3600
        transfer = db.get(Transfer, transfer_id)
        app.state.storage.delete(transfer.encrypted_storage_path)
        db.commit()
    assert (
        request(client, "get", f"/transfers/{transfer_id}/download", identities["bob"]).json()[
            "error"
        ]
        == "ENCRYPTED_FILE_MISSING"
    )


def test_storage_failure_rolls_back_state_and_nonce(client, identities, app, monkeypatch):
    exchange = establish(client, identities)
    metadata, ciphertext = package(exchange)

    def failed_write(_data):
        raise OSError("simulated disk failure")

    original_write = app.state.storage.write
    monkeypatch.setattr(app.state.storage, "write", failed_write)
    response = upload(client, identities, exchange, metadata, ciphertext)
    assert response.status_code == 503
    assert "simulated disk failure" not in response.text
    with app.state.database() as db:
        transfer = db.get(Transfer, exchange["transfer"]["id"])
        assert transfer.status == "KEY_ESTABLISHED"
        assert transfer.encrypted_storage_path is None
        assert not db.scalar(select(ConsumedNonce).where(ConsumedNonce.nonce == metadata["nonce"]))
    monkeypatch.setattr(app.state.storage, "write", original_write)
    assert upload(client, identities, exchange, metadata, ciphertext).status_code == 200


def test_upload_limit_and_header_validation(client, identities, app):
    alice = identities["alice"]
    response = request(
        client,
        "post",
        "/transfers",
        alice,
        headers={"Idempotency-Key": str(uuid.uuid4())},
        json={
            "receiver_id": identities["bob"]["user"]["id"],
            "original_filename": "large.bin",
            "file_size": app.state.settings.max_upload_bytes + 1,
        },
    )
    assert response.status_code == 413
    response = request(
        client,
        "post",
        "/transfers",
        alice,
        headers={
            "Idempotency-Key": str(uuid.uuid4()),
            "Content-Length": str(app.state.settings.max_upload_bytes + 100),
        },
        content=b"x",
    )
    assert response.status_code == 413
    exchange = establish(client, identities)
    response = request(
        client,
        "post",
        f"/transfers/{exchange['transfer']['id']}/upload",
        alice,
        content=b"x",
        headers={
            "X-Transfer-Metadata": "!invalid!",
            "X-Transfer-Signature": "x" * 200,
            "Content-Type": "application/octet-stream",
        },
    )
    assert response.json()["error"] == "INVALID_METADATA"


def test_empty_file_transfer(client, identities):
    exchange = establish(client, identities, content=b"")
    assert upload(client, identities, exchange).status_code == 200


def test_signed_key_substitution_rejected(client, identities):
    exchange = establish(client, identities)
    original = exchange["sender"]
    forged = {
        **original,
        "sender_ephemeral_public_key": crypto.b64(__import__("secrets").token_bytes(32)),
    }
    response = request(
        client,
        "post",
        "/sessions/initiate",
        identities["alice"],
        json={"metadata": forged, "signature": signed(identities["alice"], original)["signature"]},
    )
    assert response.json()["error"] == "SIGNATURE_VERIFICATION_FAILED"
    assert any(
        event["event_type"] == "MITM_DETECTED" and event["severity"] == "CRITICAL"
        for event in request(client, "get", "/security/events", identities["alice"]).json()
    )
