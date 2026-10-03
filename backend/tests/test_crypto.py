import secrets

import pytest
from app.core import crypto
from app.core.exceptions import AppError
from app.core.state_machine import FAILURES, SUCCESS_PATH, transition
from app.models import Transfer
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, x25519


def test_rsa_signatures(keys):
    metadata = crypto.canonical({"a": 1, "z": "é😀"})
    signature = crypto.sign(keys["alice"], metadata)
    assert crypto.verify(crypto.public_pem(keys["alice"].public_key()), signature, metadata)
    assert not crypto.verify(crypto.public_pem(keys["bob"].public_key()), signature, metadata)
    assert not crypto.verify(
        crypto.public_pem(keys["alice"].public_key()), signature, metadata + b"!"
    )
    assert not crypto.verify(crypto.public_pem(keys["alice"].public_key()), "bad!", metadata)


def test_matching_dh_hkdf_and_context_separation():
    a, b = x25519.X25519PrivateKey.generate(), x25519.X25519PrivateKey.generate()
    secret = a.exchange(b.public_key())
    assert secret == b.exchange(a.public_key())
    context = crypto.sha256(b"transcript")
    first = crypto.derive_key(secret, "one", context)
    assert len(first) == 32
    assert first == crypto.derive_key(secret, "one", context)
    assert first != crypto.derive_key(secret, "two", context)
    assert first != crypto.derive_key(secret, "one", crypto.sha256(b"other"))


def test_aes_authenticates_ciphertext_and_aad():
    key = secrets.token_bytes(32)
    data = b"secret\x00\xff"
    ciphertext, nonce = crypto.encrypt(key, data, b"context")
    assert crypto.decrypt(key, ciphertext, nonce, b"context") == data
    altered = bytes([ciphertext[0] ^ 1]) + ciphertext[1:]
    with pytest.raises(InvalidTag):
        crypto.decrypt(key, altered, nonce, b"context")
    with pytest.raises(InvalidTag):
        crypto.decrypt(key, ciphertext, nonce, b"wrong")
    _, another = crypto.encrypt(key, data, b"context")
    assert nonce != another


def test_sha256_known_answer():
    assert (
        crypto.sha256(b"abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    )
    assert crypto.canonical({"z": "é😀", "a": 1}) == b'{"a":1,"z":"\\u00e9\\ud83d\\ude00"}'


@pytest.mark.parametrize("value", ["bad", "A" * 44, crypto.b64(b"\0" * 32), crypto.b64(b"\1" * 31)])
def test_invalid_dh(value):
    with pytest.raises(AppError):
        crypto.validate_x25519(value)


def test_malformed_and_non_rsa_keys():
    key = ec.generate_private_key(ec.SECP256R1()).public_key()
    pem = key.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    for value in (pem, "invalid"):
        with pytest.raises(AppError):
            crypto.load_public_key(value)


@pytest.mark.parametrize(
    ("original", "safe"),
    [
        ("../../secret.txt", "secret.txt"),
        ("..\\..\\hello.txt", "hello.txt"),
        ("....", "document.bin"),
        ("CON.txt", "document.bin"),
        ("a<script>.txt", "a_script_.txt"),
        ("résumé.pdf", "r_sum_.pdf"),
    ],
)
def test_filename_sanitization(original, safe):
    assert crypto.safe_filename(original) == safe


def test_state_machine_happy_path():
    transfer = Transfer(status="CREATED", history_json="[]")
    for state in SUCCESS_PATH[1:]:
        transition(transfer, state)
    assert transfer.status == "COMPLETED"
    with pytest.raises(AppError):
        transition(transfer, "AVAILABLE")


@pytest.mark.parametrize("failure", sorted(FAILURES))
def test_failure_states_are_terminal(failure):
    transfer = Transfer(status="AVAILABLE", history_json="[]")
    transition(transfer, failure)
    with pytest.raises(AppError):
        transition(transfer, "COMPLETED")
