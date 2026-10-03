import json
from collections import Counter

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import select

from app.api.dependencies import current_user, get_db
from app.models import SecurityEvent, Transfer

router = APIRouter(prefix="/security", tags=["Security monitoring"])


def visible_events(user, db):
    transfers = select(Transfer.id).where(
        (Transfer.sender_id == user.id) | (Transfer.receiver_id == user.id)
    )
    return select(SecurityEvent).where(
        (SecurityEvent.user_id == user.id) | SecurityEvent.transfer_id.in_(transfers)
    )


@router.get("/events")
def events(limit: int = Query(100, ge=1, le=500), user=Depends(current_user), db=Depends(get_db)):
    return [
        {
            "id": event.id,
            "event_type": event.event_type,
            "severity": event.severity,
            "description": event.description,
            "user_id": event.user_id,
            "transfer_id": event.transfer_id,
            "source_ip": event.source_ip,
            "metadata": json.loads(event.metadata_json),
            "created_at": event.created_at,
            "request_id": event.request_id,
        }
        for event in db.scalars(
            visible_events(user, db).order_by(SecurityEvent.created_at.desc()).limit(limit)
        )
    ]


@router.get("/stats")
def stats(user=Depends(current_user), db=Depends(get_db)):
    records = list(db.scalars(visible_events(user, db)))
    return {
        "total": len(records),
        "by_type": dict(Counter(record.event_type for record in records)),
        "by_severity": dict(Counter(record.severity for record in records)),
    }


@router.get("/config")
def config(request: Request, user=Depends(current_user)):
    settings = request.app.state.settings
    return {
        "attack_demos_enabled": settings.enable_attack_demos,
        "max_upload_mb": settings.max_upload_mb,
        "session_expiry_minutes": settings.session_expiry_minutes,
        "replay_window_seconds": settings.replay_window_seconds,
        "login_lock_seconds": settings.login_lock_seconds,
    }
