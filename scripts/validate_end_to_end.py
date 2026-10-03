"""Run real HTTP validation against an isolated server and validate demo-user scripts."""

import json
import os
import secrets
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import httpx
from client_support import ROOT, crypto, open_vault
from cryptography.hazmat.primitives import serialization

sys.path.insert(0, str(ROOT / "backend"))
from tests.helpers import establish, package, receipt, request, signed, upload  # noqa: E402


def main():
    password = secrets.token_urlsafe(20)
    server = subprocess.Popen(
        [sys.executable, str(ROOT / "scripts/test_server.py"), "--port", "8011"],
        cwd=ROOT,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        with (
            httpx.Client(base_url="http://127.0.0.1:8011", timeout=30) as client,
            tempfile.TemporaryDirectory(prefix="secureshare-client-validation-") as folder,
        ):
            for _ in range(100):
                try:
                    if client.get("/health").status_code == 200:
                        break
                except httpx.ConnectError:
                    pass
                if server.poll() is not None:
                    raise RuntimeError("Isolated API failed to start")
                time.sleep(0.1)
            else:
                raise RuntimeError("API readiness timed out")
            subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts/create_demo_users.py"),
                    "--api",
                    "http://127.0.0.1:8011/api/v1",
                    "--output",
                    folder,
                ],
                env={**os.environ, "DEMO_PASSWORD": password},
                check=True,
                stdout=subprocess.DEVNULL,
            )
            identities = {}
            for username in ("alice", "bob", "eve"):
                vault = open_vault(
                    json.loads((Path(folder) / f"{username}.vault.json").read_text()),
                    password,
                )
                key = serialization.load_der_private_key(
                    crypto.unb64(vault["identityPrivate"]), None
                )
                challenge = client.post(
                    "/api/v1/auth/challenge", json={"username": username}
                ).json()
                result = client.post(
                    "/api/v1/auth/challenge/verify",
                    json={
                        "challenge_id": challenge["id"],
                        "signature": crypto.sign(key, crypto.canonical(challenge["metadata"])),
                    },
                )
                result.raise_for_status()
                login = result.json()
                identities[username] = {
                    "user": login["user"],
                    "key": key,
                    "password": password,
                    "headers": {"Authorization": f"Bearer {login['access_token']}"},
                }
            # Validate idempotent setup: local vaults must match the existing public identities.
            subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts/create_demo_users.py"),
                    "--api",
                    "http://127.0.0.1:8011/api/v1",
                    "--output",
                    folder,
                ],
                env={**os.environ, "DEMO_PASSWORD": password},
                check=True,
                stdout=subprocess.DEVNULL,
            )
            content = (ROOT / "docs/samples/confidential.txt").read_bytes()
            exchange = establish(client, identities, content=content, filename="confidential.txt")
            metadata, ciphertext = package(exchange)
            assert upload(client, identities, exchange, metadata, ciphertext).status_code == 200
            transfer_id = exchange["transfer"]["id"]
            downloaded = request(
                client, "get", f"/transfers/{transfer_id}/download", identities["bob"]
            )
            downloaded.raise_for_status()
            aad = {key: value for key, value in metadata.items() if key != "ciphertext_sha256"}
            assert (
                crypto.decrypt(
                    exchange["key"],
                    downloaded.content,
                    metadata["nonce"],
                    crypto.canonical(aad),
                )
                == content
            )
            done = request(
                client,
                "post",
                f"/transfers/{transfer_id}/verify",
                identities["bob"],
                json=signed(identities["bob"], receipt(exchange, identities)),
            )
            assert done.json()["status"] == "COMPLETED"
            assert (
                request(
                    client,
                    "post",
                    f"/demo/transfers/{transfer_id}/replay",
                    identities["alice"],
                ).status_code
                == 409
            )
            for attack, expected in (
                ("tamper", "FILE_TAMPERING_DETECTED"),
                ("signature", "SIGNATURE_VERIFICATION_FAILED"),
            ):
                exchange = establish(client, identities)
                assert upload(client, identities, exchange).status_code == 200
                transfer_id = exchange["transfer"]["id"]
                assert (
                    request(
                        client,
                        "post",
                        f"/demo/transfers/{transfer_id}/{attack}",
                        identities["alice"],
                    ).status_code
                    == 200
                )
                assert (
                    request(
                        client,
                        "get",
                        f"/transfers/{transfer_id}/download",
                        identities["bob"],
                    ).json()["error"]
                    == expected
                )
            assert request(client, "post", "/demo/mitm/plain", identities["alice"]).json()[
                "attacker_succeeded"
            ]
            assert not request(
                client, "post", "/demo/mitm/authenticated", identities["alice"]
            ).json()["attacker_succeeded"]
            assert request(client, "post", "/demo/brute-force", identities["alice"]).json()[
                "throttled"
            ]
            assert (
                request(client, "get", "/security/stats", identities["alice"]).json()["by_type"][
                    "MITM_DETECTED"
                ]
                > 0
            )
            assert request(client, "get", "/audit", identities["alice"]).json()
            print(
                "PASS: real API startup, health, Alice/Bob/Eve setup twice, encrypted vaults, RSA challenge login, authenticated X25519/HKDF, byte-identical transfer, signed completion, ciphertext/signature tampering, replay, both MITM demos, HTTP 429, audit and security statistics."
            )
    finally:
        server.terminate()
        try:
            server.wait(timeout=10)
        except subprocess.TimeoutExpired:
            server.kill()
            server.wait(timeout=5)


if __name__ == "__main__":
    main()
