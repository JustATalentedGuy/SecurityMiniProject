import logging

from sqlalchemy.orm import Session

from app.models import AuditLog


class AuditService:
    def __init__(self, db: Session, request_id: str):
        self.db, self.request_id = db, request_id

    def record(
        self,
        action: str,
        actor: str | None = None,
        resource: str = "system",
        resource_id: str | None = None,
    ) -> None:
        self.db.add(
            AuditLog(
                action=action,
                actor_user_id=actor,
                resource_type=resource,
                resource_id=resource_id,
                request_id=self.request_id,
            )
        )
        logging.getLogger("secureshare").info(
            "Audit action recorded",
            extra={
                "event_type": action,
                "request_id": self.request_id,
                "user_id": actor,
                "transfer_id": resource_id if resource == "transfer" else None,
            },
        )
