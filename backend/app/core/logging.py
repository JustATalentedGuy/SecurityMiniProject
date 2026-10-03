import json
import logging
from datetime import UTC, datetime


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        entry = {
            "timestamp": datetime.now(UTC).isoformat(),
            "event_type": getattr(record, "event_type", "APPLICATION"),
            "severity": getattr(record, "severity", record.levelname),
            "message": record.getMessage(),
        }
        for field in ("request_id", "user_id", "transfer_id", "source_ip", "status"):
            entry[field] = getattr(record, field, None)
        return json.dumps(entry)


def configure_logging(level: str) -> None:
    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter())
    logger = logging.getLogger("secureshare")
    logger.handlers = [handler]
    logger.setLevel(level.upper())
    logger.propagate = False
