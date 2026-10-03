import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import ValidationError
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from starlette.exceptions import HTTPException

from app.api.v1 import audit, auth, demo, security, sessions, transfers, users
from app.core.config import Settings
from app.core.crypto import sha256
from app.core.exceptions import AppError
from app.core.logging import configure_logging
from app.db.database import Base, create_database
from app.middleware.rate_limit import RateLimiter
from app.middleware.request_id import RequestContextMiddleware
from app.models import AuthToken
from app.services.security_event_service import SecurityEventService
from app.services.storage_service import LocalEncryptedStorage


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings()
    configure_logging(settings.log_level)
    engine, database = create_database(settings.database_url)

    @asynccontextmanager
    async def lifespan(_app):
        Base.metadata.create_all(engine)
        yield
        engine.dispose()

    app = FastAPI(
        title="SecureShare-X",
        version="1.0.0",
        description="Encrypted file exchange with client-side authenticated cryptography.",
        lifespan=lifespan,
    )
    app.state.settings, app.state.engine, app.state.database = settings, engine, database
    app.state.storage = LocalEncryptedStorage(settings.storage_path)
    app.state.limiter = RateLimiter(settings.rate_limit_window_seconds)

    def body_limit_event(scope, request_id):
        with database() as db:
            authorization = (
                dict(scope.get("headers", [])).get(b"authorization", b"").decode(errors="ignore")
            )
            token = (
                db.get(AuthToken, sha256(authorization[7:].encode()))
                if authorization.startswith("Bearer ")
                else None
            )
            SecurityEventService(db, request_id, scope.get("client", (None,))[0]).record(
                "UPLOAD_LIMIT_EXCEEDED",
                "MEDIUM",
                "An oversized request was rejected before reading its body.",
                token.user_id if token else None,
            )
            db.commit()

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=False,
        allow_methods=["GET", "POST"],
        allow_headers=[
            "Authorization",
            "Content-Type",
            "Idempotency-Key",
            "X-Transfer-Metadata",
            "X-Transfer-Signature",
        ],
        expose_headers=["X-Request-ID", "Retry-After"],
    )
    app.add_middleware(
        RequestContextMiddleware,
        max_upload_bytes=settings.max_upload_bytes,
        on_limit=body_limit_event,
    )

    def error_response(request, code, message, status):
        response = JSONResponse(
            {
                "error": code,
                "message": message,
                "request_id": getattr(request.state, "request_id", None),
            },
            status_code=status,
        )
        if status == 500:
            response.headers["X-Request-ID"] = getattr(request.state, "request_id", "")
        if status == 429:
            response.headers["Retry-After"] = str(
                max(settings.rate_limit_window_seconds, settings.login_lock_seconds)
            )
        return response

    @app.exception_handler(AppError)
    async def application_error(request: Request, exc: AppError):
        return error_response(request, exc.code, exc.message, exc.status_code)

    @app.exception_handler(RequestValidationError)
    @app.exception_handler(ValidationError)
    async def validation_error(request: Request, _exc):
        return error_response(
            request, "INVALID_INPUT", "Check the supplied fields and cryptographic metadata.", 422
        )

    @app.exception_handler(HTTPException)
    async def http_error(request: Request, exc):
        return error_response(
            request,
            "NOT_FOUND" if exc.status_code == 404 else "HTTP_ERROR",
            "The requested operation is unavailable.",
            exc.status_code,
        )

    @app.exception_handler(IntegrityError)
    async def conflict_error(request: Request, _exc):
        return error_response(
            request,
            "DATABASE_CONFLICT",
            "A duplicate or concurrent request conflicts with an existing record. Refresh and retry.",
            409,
        )

    @app.exception_handler(SQLAlchemyError)
    async def database_error(request: Request, _exc):
        logging.getLogger("secureshare").error(
            "Database operation failed",
            extra={"request_id": request.state.request_id, "event_type": "DATABASE_ERROR"},
        )
        return error_response(
            request, "DATABASE_UNAVAILABLE", "The operation could not be saved. Please retry.", 503
        )

    @app.exception_handler(Exception)
    async def unexpected_error(request: Request, _exc):
        logging.getLogger("secureshare").error(
            "Unexpected operation failure",
            extra={
                "request_id": getattr(request.state, "request_id", None),
                "event_type": "INTERNAL_ERROR",
            },
        )
        return error_response(
            request,
            "INTERNAL_ERROR",
            "The operation failed. Use the request ID to investigate.",
            500,
        )

    @app.get("/health", tags=["Health"])
    @app.get("/api/v1/health", tags=["Health"])
    def health():
        database_ok = True
        try:
            with engine.connect() as connection:
                connection.execute(text("SELECT 1"))
        except SQLAlchemyError:
            database_ok = False
        storage_ok = app.state.storage.healthy()
        healthy = database_ok and storage_ok
        return JSONResponse(
            {
                "status": "ok" if healthy else "degraded",
                "application": True,
                "database": database_ok,
                "storage": storage_ok,
            },
            status_code=200 if healthy else 503,
        )

    for router in (
        auth.router,
        users.router,
        sessions.router,
        transfers.router,
        security.router,
        audit.router,
    ):
        app.include_router(router, prefix="/api/v1")
    if settings.enable_attack_demos:
        app.include_router(demo.router, prefix="/api/v1")
    return app


app = create_app()
