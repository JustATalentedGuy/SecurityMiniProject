from fastapi import APIRouter, Depends, Query
from sqlalchemy import select

from app.api.dependencies import current_user, get_db
from app.models import AuditLog, Transfer

router = APIRouter(prefix="/audit", tags=["Audit records"])


@router.get("")
def audit(limit: int = Query(100, ge=1, le=500), user=Depends(current_user), db=Depends(get_db)):
    transfers = select(Transfer.id).where(
        (Transfer.sender_id == user.id) | (Transfer.receiver_id == user.id)
    )
    query = (
        select(AuditLog)
        .where(
            (AuditLog.actor_user_id == user.id)
            | ((AuditLog.resource_type == "transfer") & AuditLog.resource_id.in_(transfers))
        )
        .order_by(AuditLog.created_at.desc())
        .limit(limit)
    )
    return [
        {
            "id": record.id,
            "actor_user_id": record.actor_user_id,
            "action": record.action,
            "resource_type": record.resource_type,
            "resource_id": record.resource_id,
            "request_id": record.request_id,
            "created_at": record.created_at,
        }
        for record in db.scalars(query)
    ]
