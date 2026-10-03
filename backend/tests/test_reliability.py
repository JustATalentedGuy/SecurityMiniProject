import json
import time

import pytest
from app.models import AuditLog, AuthToken, SecureSession, Transfer
from sqlalchemy import select
from sqlalchemy.exc import OperationalError

from tests.helpers import establish, package, receipt, request, signed, upload


def test_client_rejection_before_download_is_recorded(client, identities):
    exchange = establish(client, identities)
    assert upload(client, identities, exchange).status_code == 200
    transfer_id = exchange["transfer"]["id"]
    metadata = receipt(exchange, identities, result="SIGNATURE_INVALID")
    metadata["plaintext_sha256"] = None
    result = request(
        client,
        "post",
        f"/transfers/{transfer_id}/verify",
        identities["bob"],
        json=signed(identities["bob"], metadata),
    )
    assert result.status_code == 200
    assert result.json()["status"] == "SIGNATURE_INVALID"
    assert any(
        event["event_type"] == "SIGNATURE_INVALID"
        for event in request(client, "get", "/security/events", identities["alice"]).json()
    )


def test_database_commit_failure_removes_ciphertext_object(client, identities, app, monkeypatch):
    from sqlalchemy.orm import Session

    exchange = establish(client, identities)
    metadata, ciphertext = package(exchange)
    original_commit = Session.commit

    def failing_commit(db):
        if any(
            isinstance(record, Transfer) and record.encrypted_storage_path for record in db.dirty
        ):
            raise OperationalError("commit", {}, Exception("simulated commit failure"))
        return original_commit(db)

    monkeypatch.setattr(Session, "commit", failing_commit)
    response = upload(client, identities, exchange, metadata, ciphertext)
    assert response.status_code == 503
    assert response.json()["error"] == "DATABASE_UNAVAILABLE"
    assert list(app.state.storage.root.glob("*.enc")) == []
    with app.state.database() as db:
        transfer = db.get(Transfer, exchange["transfer"]["id"])
        assert transfer.status == "KEY_ESTABLISHED"
        assert transfer.encrypted_storage_path is None
    monkeypatch.setattr(Session, "commit", original_commit)
    assert upload(client, identities, exchange, metadata, ciphertext).status_code == 200


def test_expired_bearer_token_is_rejected(client, identities, app):
    with app.state.database() as db:
        for token in db.scalars(select(AuthToken)):
            token.expires_at = time.time() - 1
        db.commit()
    assert request(client, "get", "/auth/me", identities["alice"]).status_code == 401


def test_audit_records_cannot_be_edited_or_deleted(client, identities, app):
    for remove in (False, True):
        with app.state.database() as db:
            record = db.scalar(select(AuditLog))
            if remove:
                db.delete(record)
            else:
                record.action = "REWRITTEN"
            with pytest.raises(ValueError, match="append-only"):
                db.commit()
            db.rollback()


def test_valid_sessions_and_registry_queries(client, identities):
    exchange = establish(client, identities)
    alice = identities["alice"]
    assert len(request(client, "get", "/users", alice).json()) == 3
    assert request(
        client, "get", f"/users/{identities['bob']['user']['id']}/public-key", alice
    ).json()["fingerprint"]
    assert len(request(client, "get", "/sessions", alice).json()) == 1
    assert (
        request(client, "get", f"/sessions/{exchange['session_id']}", alice).json()["status"]
        == "ESTABLISHED"
    )
    assert request(client, "get", "/security/config", alice).json()["max_upload_mb"] == 25


def test_low_order_public_key_and_unsigned_extra_fields_rejected(client, identities):
    exchange = establish(client, identities)
    metadata = {
        **exchange["sender"],
        "sender_ephemeral_public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    }
    response = request(
        client,
        "post",
        "/sessions/initiate",
        identities["alice"],
        json=signed(identities["alice"], metadata),
    )
    assert response.status_code == 400
    assert response.json()["error"] == "INVALID_DH_KEY"
    metadata = {**exchange["sender"], "private_key": "should-never-be-accepted"}
    response = request(
        client,
        "post",
        "/sessions/initiate",
        identities["alice"],
        json=signed(identities["alice"], metadata),
    )
    assert response.status_code == 422
    assert "should-never-be-accepted" not in response.text


def test_header_and_streamed_upload_limits(client, identities, app):
    exchange = establish(client, identities)
    metadata, ciphertext = package(exchange)
    transfer_id = exchange["transfer"]["id"]
    alice = identities["alice"]
    response = request(
        client,
        "post",
        f"/transfers/{transfer_id}/upload",
        alice,
        content=ciphertext,
        headers={
            "Content-Type": "text/plain",
            "X-Transfer-Metadata": "e30=",
            "X-Transfer-Signature": "x" * 200,
        },
    )
    assert response.status_code == 415
    app.state.settings.max_upload_mb = 1
    response = request(
        client,
        "post",
        f"/transfers/{transfer_id}/upload",
        alice,
        content=(b"x" * 600000 for _ in range(2)),
        headers={
            "Content-Type": "application/octet-stream",
            "X-Transfer-Metadata": __import__("base64")
            .b64encode(json.dumps(metadata).encode())
            .decode(),
            "X-Transfer-Signature": signed(alice, metadata)["signature"],
        },
    )
    assert response.status_code == 413


def test_modified_confirmation_transcript_rejected(client, identities, app):
    exchange = establish(client, identities)
    with app.state.database() as db:
        session = db.get(SecureSession, exchange["session_id"])
        session.status = "RESPONDED"
        db.get(Transfer, exchange["transfer"]["id"]).status = "KEY_EXCHANGE_PENDING"
        db.commit()
    metadata = {
        "protocol": "secureshare-x/v1",
        "purpose": "dh-confirm",
        "transfer_id": exchange["transfer"]["id"],
        "session_identifier": exchange["sender"]["session_identifier"],
        "transcript_sha256": "0" * 64,
        "timestamp": int(time.time()),
        "nonce": __import__("secrets").token_hex(16),
    }
    response = request(
        client,
        "post",
        f"/sessions/{exchange['session_id']}/verify",
        identities["alice"],
        json=signed(identities["alice"], metadata),
    )
    assert response.json()["error"] == "MITM_DETECTED"
