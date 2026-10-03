import secrets

import pytest
from app.core.config import Settings
from app.core.crypto import public_pem
from app.main import create_app
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient


@pytest.fixture(scope="session")
def keys():
    return {
        name: rsa.generate_private_key(public_exponent=65537, key_size=2048)
        for name in ("alice", "bob", "eve")
    }


@pytest.fixture
def app(tmp_path):
    return create_app(
        Settings(
            database_url=f"sqlite:///{tmp_path / 'test.db'}",
            storage_path=tmp_path / "objects",
            rate_limit_login=1000,
            rate_limit_upload=1000,
            rate_limit_verification=1000,
            log_level="ERROR",
        )
    )


@pytest.fixture
def client(app):
    with TestClient(app) as client:
        yield client


@pytest.fixture
def identities(client, keys):
    password = secrets.token_urlsafe(18)
    result = {}
    for name, key in keys.items():
        data = {
            "username": name,
            "password": password,
            "public_key_pem": public_pem(key.public_key()),
        }
        response = client.post("/api/v1/auth/register", json=data)
        assert response.status_code == 201, response.text
        login = client.post(
            "/api/v1/auth/login", json={"username": name, "password": password}
        ).json()
        result[name] = {
            "user": response.json(),
            "key": key,
            "password": password,
            "headers": {"Authorization": f"Bearer {login['access_token']}"},
        }
    return result
