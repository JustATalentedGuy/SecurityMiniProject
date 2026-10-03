import time

from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.core.crypto import sha256
from app.core.exceptions import AppError
from app.models import AuthToken, User
from app.services.audit_service import AuditService
from app.services.security_event_service import SecurityEventService

bearer = HTTPBearer(auto_error=False)


def get_db(request: Request):
    with request.app.state.database() as db:
        try:
            yield db
            db.commit()
        except Exception:
            db.rollback()
            raise


def current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer), db=Depends(get_db)
) -> User:
    if not credentials:
        raise AppError("AUTHENTICATION_REQUIRED", "Sign in to continue.", 401)
    token = db.get(AuthToken, sha256(credentials.credentials.encode()))
    if not token or token.expires_at <= time.time():
        raise AppError(
            "TOKEN_EXPIRED", "Your authentication session has expired. Sign in again.", 401
        )
    user = db.get(User, token.user_id)
    if not user or not user.is_active:
        raise AppError("AUTHENTICATION_REQUIRED", "This identity is unavailable.", 401)
    return user


def services(request: Request, db=Depends(get_db)):
    events = SecurityEventService(
        db, request.state.request_id, request.client.host if request.client else None
    )
    audit = AuditService(db, request.state.request_id)
    return db, request.app.state.settings, events, audit


def rate_limit(category: str):
    def check(request: Request, svc=Depends(services)):
        db, settings, events, _audit = svc
        limit = {
            "login": settings.rate_limit_login,
            "register": 8,
            "challenge": 20,
            "verify": settings.rate_limit_verification,
            "upload": settings.rate_limit_upload,
            "demo": 20,
        }[category]
        source = request.client.host if request.client else "unknown"
        if not request.app.state.limiter.allow(f"{category}:{source}", limit):
            authorization = request.headers.get("Authorization", "")
            token = (
                db.get(AuthToken, sha256(authorization[7:].encode()))
                if authorization.startswith("Bearer ")
                else None
            )
            events.reject(
                "RATE_LIMIT_EXCEEDED",
                "MEDIUM",
                "Too many requests; wait for the rate-limit window to reset.",
                token.user_id if token and token.expires_at > time.time() else None,
                status=429,
            )

    return check
