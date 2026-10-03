import json
import logging

from sqlalchemy.orm import Session

from app.core.exceptions import AppError
from app.models import SecurityEvent
from app.services.audit_service import AuditService


class SecurityEventService:
    def __init__(self, db: Session, request_id: str, source_ip: str | None):
        self.db, self.request_id, self.source_ip = db, request_id, source_ip

    def record(
        self,
        event_type: str,
        severity: str,
        description: str,
        user_id: str | None = None,
        transfer_id: str | None = None,
        metadata: dict | None = None,
    ) -> None:
        self.db.add(
            SecurityEvent(
                event_type=event_type,
                severity=severity,
                description=description,
                user_id=user_id,
                transfer_id=transfer_id,
                source_ip=self.source_ip,
                metadata_json=json.dumps(metadata or {}),
                request_id=self.request_id,
            )
        )
        AuditService(self.db, self.request_id).record(
            event_type, user_id, "transfer" if transfer_id else "security", transfer_id
        )
        logging.getLogger("secureshare").info(
            description,
            extra={
                "event_type": event_type,
                "request_id": self.request_id,
                "user_id": user_id,
                "transfer_id": transfer_id,
                "source_ip": self.source_ip,
                "status": severity,
                "severity": severity,
            },
        )

    def reject(
        self,
        event_type: str,
        severity: str,
        message: str,
        user_id: str | None = None,
        transfer_id: str | None = None,
        status: int = 400,
        code: str | None = None,
    ) -> None:
        self.record(event_type, severity, message, user_id, transfer_id)
        self.db.commit()  # preserve rejection evidence even though the request raises
        raise AppError(code or event_type, message, status)
