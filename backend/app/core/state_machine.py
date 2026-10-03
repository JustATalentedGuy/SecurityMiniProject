import json
import time

from app.core.exceptions import AppError
from app.models import Transfer

SUCCESS_PATH = [
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
FAILURES = {"REJECTED", "TAMPERED", "SIGNATURE_INVALID", "REPLAY_REJECTED", "FAILED"}
TRANSITIONS = {state: {SUCCESS_PATH[index + 1]} for index, state in enumerate(SUCCESS_PATH[:-1])}
for state in SUCCESS_PATH[:-2]:
    TRANSITIONS[state] |= FAILURES


def transition(transfer: Transfer, target: str) -> None:
    if target not in TRANSITIONS.get(transfer.status, set()):
        raise AppError(
            "INVALID_STATE_TRANSITION", f"Cannot change {transfer.status} to {target}.", 409
        )
    transfer.status = target
    transfer.updated_at = time.time()
    history = json.loads(transfer.history_json or "[]")
    history.append({"status": target, "timestamp": transfer.updated_at})
    transfer.history_json = json.dumps(history)
