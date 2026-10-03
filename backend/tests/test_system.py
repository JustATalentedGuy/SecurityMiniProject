import time

import pytest
from app.core.config import Settings
from app.core.exceptions import AppError
from app.main import create_app
from app.middleware.rate_limit import RateLimiter
from app.models import AuditLog, SecurityEvent
from app.services.storage_service import LocalEncryptedStorage
from fastapi.testclient import TestClient
from sqlalchemy import select

from tests.helpers import establish, request, upload


def test_health_audit_and_security_stats(client, identities, app):
    for path in ("/health", "/api/v1/health"):
        response = client.get(path)
        assert response.status_code == 200
        assert response.json() == {
            "status": "ok",
            "application": True,
            "database": True,
            "storage": True,
        }
    audit = request(client, "get", "/audit", identities["alice"]).json()
    assert any(record["action"] == "USER_REGISTERED" and record["request_id"] for record in audit)
    stats = request(client, "get", "/security/stats", identities["alice"]).json()
    assert stats["by_type"]["LOGIN_SUCCESS"] == 1
    assert stats["by_severity"]["INFO"] == 1
    with app.state.database() as db:
        assert db.scalar(select(AuditLog))
        assert db.scalar(select(SecurityEvent))


def test_request_rate_limit_returns_429_and_retry_after(client, app):
    app.state.settings.rate_limit_login = 2
    for _ in range(2):
        assert (
            client.post(
                "/api/v1/auth/login", json={"username": "unknown", "password": "wrong"}
            ).status_code
            == 401
        )
    limited = client.post("/api/v1/auth/login", json={"username": "unknown", "password": "wrong"})
    assert limited.status_code == 429
    assert int(limited.headers["Retry-After"]) > 0
    with app.state.database() as db:
        assert db.scalar(
            select(SecurityEvent).where(SecurityEvent.event_type == "RATE_LIMIT_EXCEEDED")
        )


def test_rate_limiter_window_resets():
    limiter = RateLimiter(0.02)
    assert limiter.allow("key", 1)
    assert not limiter.allow("key", 1)
    time.sleep(0.03)
    assert limiter.allow("key", 1)


def test_demo_mitm_and_brute_force(client, identities):
    alice = identities["alice"]
    insecure = request(client, "post", "/demo/mitm/plain", alice).json()
    assert insecure["attacker_succeeded"]
    assert insecure["alice_eve_secret_matches"] and insecure["eve_bob_secret_matches"]
    assert not insecure["alice_bob_secret_matches"]
    secure = request(client, "post", "/demo/mitm/authenticated", alice).json()
    assert not secure["attacker_succeeded"] and not secure["signature_valid"]
    brute = request(client, "post", "/demo/brute-force", alice).json()
    assert brute["throttled"] and brute["statuses"][-1] == 429


def test_replay_demo(client, identities):
    exchange = establish(client, identities)
    upload(client, identities, exchange)
    response = request(
        client, "post", f"/demo/transfers/{exchange['transfer']['id']}/replay", identities["alice"]
    )
    assert response.status_code == 409
    assert response.json()["error"] == "REPLAY_ATTACK_DETECTED"


def test_demo_endpoints_disabled(tmp_path):
    app = create_app(
        Settings(
            database_url=f"sqlite:///{tmp_path / 'off.db'}",
            storage_path=tmp_path / "storage",
            enable_attack_demos=False,
            log_level="ERROR",
        )
    )
    with TestClient(app) as client:
        assert client.post("/api/v1/demo/mitm/plain").status_code == 404
        assert not any("/demo/" in path for path in client.get("/openapi.json").json()["paths"])


def test_storage_traversal_rejection_and_atomic_objects(tmp_path):
    storage = LocalEncryptedStorage(tmp_path)
    object_id = storage.write(b"ciphertext")
    assert storage.read(object_id) == b"ciphertext"
    assert storage.healthy()
    for path in ("../outside", "C:\\secret", "../../x.enc", "invalid.enc"):
        with pytest.raises(AppError):
            storage.read(path)
    storage.delete(object_id)
    assert not list(tmp_path.glob("*.tmp"))
    with pytest.raises(AppError):
        storage.read(object_id)


def test_health_degraded(client, app, monkeypatch):
    monkeypatch.setattr(app.state.storage, "healthy", lambda: False)
    response = client.get("/health")
    assert response.status_code == 503
    assert response.json()["storage"] is False
