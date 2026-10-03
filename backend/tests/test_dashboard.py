import time

from app.models import SecureSession

from tests.helpers import establish, receipt, request, signed, upload


def test_dashboard_aggregates_and_pending_count(client, identities):
    alice, bob, eve = identities["alice"], identities["bob"], identities["eve"]
    assert request(client, "get", "/transfers/stats", alice).json()["sent"] == 0
    exchange = establish(client, identities)
    assert upload(client, identities, exchange).status_code == 200
    sent = request(client, "get", "/transfers/stats", alice).json()
    assert sent["sent"] == sent["pending"] == 1
    received = request(client, "get", "/transfers/stats", bob).json()
    assert received["received"] == 1
    assert request(client, "get", "/transfers/stats", eve).json()["pending"] == 0


def test_expired_session_cannot_complete_with_fresh_receipt(client, identities, app):
    exchange = establish(client, identities)
    assert upload(client, identities, exchange).status_code == 200
    transfer_id = exchange["transfer"]["id"]
    assert (
        request(client, "get", f"/transfers/{transfer_id}/download", identities["bob"]).status_code
        == 200
    )
    with app.state.database() as db:
        db.get(SecureSession, exchange["session_id"]).expires_at = time.time() - 1
        db.commit()
    response = request(
        client,
        "post",
        f"/transfers/{transfer_id}/verify",
        identities["bob"],
        json=signed(identities["bob"], receipt(exchange, identities)),
    )
    assert response.json()["error"] == "SESSION_EXPIRED"
