import time
import uuid

from app.core import crypto
from cryptography.hazmat.primitives.asymmetric import x25519


def signed(identity, metadata):
    return {
        "metadata": metadata,
        "signature": crypto.sign(identity["key"], crypto.canonical(metadata)),
    }


def request(client, method, path, identity, **kwargs):
    headers = {**identity["headers"], **kwargs.pop("headers", {})}
    return getattr(client, method)("/api/v1" + path, headers=headers, **kwargs)


def establish(
    client, identities, content=b"Confidential lab data\x00\xff\n", filename="confidential.pdf"
):
    alice, bob = identities["alice"], identities["bob"]
    response = request(
        client,
        "post",
        "/transfers",
        alice,
        headers={"Idempotency-Key": str(uuid.uuid4())},
        json={
            "receiver_id": bob["user"]["id"],
            "original_filename": filename,
            "file_size": len(content),
            "mime_type": "application/pdf",
        },
    )
    assert response.status_code == 201, response.text
    transfer = response.json()
    a, b = x25519.X25519PrivateKey.generate(), x25519.X25519PrivateKey.generate()
    sender = {
        "protocol": crypto.PROTOCOL,
        "purpose": "dh-initiate",
        "transfer_id": transfer["id"],
        "session_identifier": str(uuid.uuid4()),
        "sender_id": alice["user"]["id"],
        "receiver_id": bob["user"]["id"],
        "sender_ephemeral_public_key": crypto.b64(a.public_key().public_bytes_raw()),
        "receiver_ephemeral_public_key": None,
        "timestamp": int(time.time()),
        "nonce": uuid.uuid4().hex,
    }
    response = request(client, "post", "/sessions/initiate", alice, json=signed(alice, sender))
    assert response.status_code == 200, response.text
    session_id = response.json()["id"]
    receiver = {
        **sender,
        "purpose": "dh-respond",
        "receiver_ephemeral_public_key": crypto.b64(b.public_key().public_bytes_raw()),
        "timestamp": int(time.time()),
        "nonce": uuid.uuid4().hex,
    }
    response = request(
        client, "post", f"/sessions/{session_id}/respond", bob, json=signed(bob, receiver)
    )
    assert response.status_code == 200, response.text
    transcript = crypto.transcript_hash(sender, receiver)
    confirmation = {
        "protocol": crypto.PROTOCOL,
        "purpose": "dh-confirm",
        "transfer_id": transfer["id"],
        "session_identifier": sender["session_identifier"],
        "transcript_sha256": transcript,
        "timestamp": int(time.time()),
        "nonce": uuid.uuid4().hex,
    }
    response = request(
        client, "post", f"/sessions/{session_id}/verify", alice, json=signed(alice, confirmation)
    )
    assert response.status_code == 200, response.text
    ka = crypto.derive_key(a.exchange(b.public_key()), sender["session_identifier"], transcript)
    kb = crypto.derive_key(b.exchange(a.public_key()), sender["session_identifier"], transcript)
    assert ka == kb
    return {
        "transfer": transfer,
        "session_id": session_id,
        "sender": sender,
        "receiver": receiver,
        "key": kb,
        "content": content,
        "transcript": transcript,
    }


def package(exchange):
    transfer, sender = exchange["transfer"], exchange["sender"]
    nonce = crypto.b64(__import__("secrets").token_bytes(12))
    metadata = {
        "protocol": crypto.PROTOCOL,
        "purpose": "file-transfer",
        "transfer_id": transfer["id"],
        "session_identifier": sender["session_identifier"],
        "sender_id": transfer["sender_id"],
        "receiver_id": transfer["receiver_id"],
        "filename": transfer["safe_filename"],
        "mime_type": transfer["mime_type"],
        "file_size": len(exchange["content"]),
        "plaintext_sha256": crypto.sha256(exchange["content"]),
        "transcript_sha256": exchange["transcript"],
        "nonce": nonce,
        "timestamp": int(time.time()),
    }
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    ciphertext = AESGCM(exchange["key"]).encrypt(
        crypto.unb64(nonce), exchange["content"], crypto.canonical(metadata)
    )
    metadata["ciphertext_sha256"] = crypto.sha256(ciphertext)
    return metadata, ciphertext


def upload(client, identities, exchange, metadata=None, ciphertext=None, signature=None):
    if metadata is None:
        metadata, ciphertext = package(exchange)
    signature = signature or crypto.sign(identities["alice"]["key"], crypto.canonical(metadata))
    return request(
        client,
        "post",
        f"/transfers/{exchange['transfer']['id']}/upload",
        identities["alice"],
        content=ciphertext,
        headers={
            "Content-Type": "application/octet-stream",
            "X-Transfer-Metadata": crypto.b64(crypto.canonical(metadata)),
            "X-Transfer-Signature": signature,
        },
    )


def receipt(exchange, identities, result="VERIFIED", file_hash=None):
    return {
        "protocol": crypto.PROTOCOL,
        "purpose": "transfer-receipt",
        "transfer_id": exchange["transfer"]["id"],
        "receiver_id": identities["bob"]["user"]["id"],
        "result": result,
        "plaintext_sha256": file_hash or crypto.sha256(exchange["content"]),
        "timestamp": int(time.time()),
        "nonce": uuid.uuid4().hex,
    }
