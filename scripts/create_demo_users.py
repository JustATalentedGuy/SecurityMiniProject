"""Create Alice, Bob, Eve via the real API and encrypted browser-compatible local vaults."""

import argparse
import getpass
import json
import os
from pathlib import Path

import httpx
from client_support import ROOT, crypto, open_vault, seal_vault, vault_for_key
from cryptography.hazmat.primitives.asymmetric import rsa


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--api", default="http://127.0.0.1:8000/api/v1")
    parser.add_argument("--output", type=Path, default=ROOT / "demo-clients")
    args = parser.parse_args()
    password = os.environ.get("DEMO_PASSWORD") or getpass.getpass(
        "Choose a demo password (at least 10 characters; not stored): "
    )
    if not 10 <= len(password) <= 128:
        raise SystemExit("Password must be 10–128 characters.")
    args.output.mkdir(parents=True, exist_ok=True)
    with httpx.Client(timeout=30) as client:
        client.get(args.api + "/health").raise_for_status()
        for username in ("alice", "bob", "eve"):
            path = args.output / f"{username}.vault.json"
            vault = (
                open_vault(json.loads(path.read_text()), password)
                if path.exists()
                else vault_for_key(
                    username,
                    rsa.generate_private_key(public_exponent=65537, key_size=3072),
                )
            )
            response = client.post(
                args.api + "/auth/register",
                json={
                    "username": username,
                    "password": password,
                    "public_key_pem": vault["publicKeyPem"],
                },
            )
            if response.status_code == 409:
                login = client.post(
                    args.api + "/auth/login",
                    json={"username": username, "password": password},
                )
                login.raise_for_status()
                identity = login.json()
                if identity["user"]["fingerprint"] != crypto.fingerprint(vault["publicKeyPem"]):
                    raise SystemExit(
                        f"{username} already has a different identity. Restore its vault or reset the disposable demo database."
                    )
                client.post(
                    args.api + "/auth/logout",
                    headers={"Authorization": f"Bearer {identity['access_token']}"},
                )
            else:
                response.raise_for_status()
            if not path.exists():
                path.write_text(json.dumps(seal_vault(vault, password), indent=2), encoding="utf-8")
            print(f"{username}: encrypted local vault at {path}")
    print(
        "Import the appropriate vault on the browser login screen. Private keys were never uploaded."
    )


if __name__ == "__main__":
    main()
