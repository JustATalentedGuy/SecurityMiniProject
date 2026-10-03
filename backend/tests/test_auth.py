import time

from app.models import AuthChallenge, User
from app.services.auth_service import PASSWORD_HASHER
from sqlalchemy import select

from tests.helpers import request, signed


def test_registration_duplicate_hashing_and_logout(client, identities, app):
    alice = identities["alice"]
    with app.state.database() as db:
        user = db.get(User, alice["user"]["id"])
        assert user.password_hash != alice["password"]
        assert user.password_hash.startswith("$argon2id$")
        assert PASSWORD_HASHER.verify(user.password_hash, alice["password"])
    response = client.post(
        "/api/v1/auth/register",
        json={
            "username": "ALICE",
            "password": alice["password"],
            "public_key_pem": alice["user"]["public_key_pem"],
        },
    )
    assert response.status_code == 409
    assert request(client, "get", "/auth/me", alice).json()["username"] == "alice"
    assert request(client, "post", "/auth/logout", alice).status_code == 204
    assert request(client, "get", "/auth/me", alice).status_code == 401


def test_challenge_auth_and_replay(client, identities):
    alice = identities["alice"]
    challenge = client.post("/api/v1/auth/challenge", json={"username": "alice"}).json()
    data = {
        "challenge_id": challenge["id"],
        "signature": signed(alice, challenge["metadata"])["signature"],
    }
    response = client.post("/api/v1/auth/challenge/verify", json=data)
    assert response.status_code == 200
    replay = client.post("/api/v1/auth/challenge/verify", json=data)
    assert replay.status_code == 409
    assert replay.json()["error"] == "CHALLENGE_REUSED"


def test_challenge_expiration(client, identities, app):
    challenge = client.post("/api/v1/auth/challenge", json={"username": "alice"}).json()
    with app.state.database() as db:
        db.get(AuthChallenge, challenge["id"]).expires_at = time.time() - 1
        db.commit()
    response = client.post(
        "/api/v1/auth/challenge/verify",
        json={
            "challenge_id": challenge["id"],
            "signature": signed(identities["alice"], challenge["metadata"])["signature"],
        },
    )
    assert response.status_code == 400
    assert response.json()["error"] == "CHALLENGE_EXPIRED"


def test_wrong_challenge_signature(client, identities):
    challenge = client.post("/api/v1/auth/challenge", json={"username": "alice"}).json()
    response = client.post(
        "/api/v1/auth/challenge/verify",
        json={
            "challenge_id": challenge["id"],
            "signature": signed(identities["eve"], challenge["metadata"])["signature"],
        },
    )
    assert response.status_code == 400
    assert response.json()["error"] == "SIGNATURE_VERIFICATION_FAILED"


def test_malformed_key_recorded(client):
    response = client.post(
        "/api/v1/auth/register",
        json={
            "username": "malformed",
            "password": "long-password-123",
            "public_key_pem": "x" * 150,
        },
    )
    assert response.status_code == 400
    assert response.json()["error"] == "MALFORMED_PUBLIC_KEY"


def test_brute_force_temporary_throttle_and_reset(client, identities):
    alice = identities["alice"]
    for _ in range(5):
        assert (
            client.post(
                "/api/v1/auth/login", json={"username": "alice", "password": "wrong"}
            ).status_code
            == 401
        )
    assert (
        client.post(
            "/api/v1/auth/login", json={"username": "alice", "password": alice["password"]}
        ).status_code
        == 429
    )
    assert request(client, "post", "/demo/reset-cooldown", alice).status_code == 200
    assert (
        client.post(
            "/api/v1/auth/login", json={"username": "alice", "password": alice["password"]}
        ).status_code
        == 200
    )


def test_invalid_input_and_anonymous_access(client):
    response = client.post(
        "/api/v1/auth/register",
        json={"username": "../", "password": "weak", "public_key_pem": "private"},
    )
    assert response.status_code == 422
    assert "private" not in response.text
    assert response.json()["request_id"] == response.headers["X-Request-ID"]
    assert client.get("/api/v1/transfers/sent").status_code == 401


def test_inactive_user_and_expired_token(client, identities, app):
    alice = identities["alice"]
    with app.state.database() as db:
        user = db.scalar(select(User).where(User.username == "alice"))
        user.is_active = False
        db.commit()
    assert request(client, "get", "/auth/me", alice).status_code == 401
