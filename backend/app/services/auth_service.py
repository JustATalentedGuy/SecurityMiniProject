import secrets
import time

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from sqlalchemy import case, update
from sqlalchemy.orm import Session

from app.core import crypto
from app.core.config import Settings
from app.core.exceptions import AppError
from app.models import AuthChallenge, AuthToken, User
from app.repositories.repository import Repository
from app.schemas import ChallengeVerify, Login, Register
from app.services.audit_service import AuditService
from app.services.security_event_service import SecurityEventService
from app.services.user_service import user_view

PASSWORD_HASHER = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2)
DUMMY_HASH = PASSWORD_HASHER.hash(secrets.token_urlsafe(32))


def challenge_metadata(challenge: AuthChallenge) -> dict:
    return {
        "protocol": crypto.PROTOCOL,
        "purpose": "login-challenge",
        "challenge_id": challenge.id,
        "user_id": challenge.user_id,
        "challenge": challenge.challenge,
        "expires_at": int(challenge.expires_at),
    }


class AuthService:
    def __init__(
        self, db: Session, settings: Settings, events: SecurityEventService, audit: AuditService
    ):
        self.db, self.settings, self.events, self.audit = db, settings, events, audit
        self.repository = Repository(db)

    def register(self, data: Register) -> dict:
        if self.repository.username(data.username):
            raise AppError("USERNAME_EXISTS", "This username is already registered.", 409)
        try:
            pem = crypto.public_pem(crypto.load_public_key(data.public_key_pem))
        except AppError:
            self.events.reject(
                "MALFORMED_KEY",
                "HIGH",
                "Registration supplied a malformed RSA public key.",
                code="MALFORMED_PUBLIC_KEY",
            )
        user = User(
            username=data.username.lower(),
            password_hash=PASSWORD_HASHER.hash(data.password),
            public_key_pem=pem,
        )
        self.db.add(user)
        self.db.flush()
        self.audit.record("USER_REGISTERED", user.id, "user", user.id)
        return user_view(user)

    def _blocked(self, user: User) -> None:
        if user.blocked_until > time.time():
            self.events.reject(
                "RATE_LIMIT_EXCEEDED",
                "MEDIUM",
                "Too many authentication failures. Try again after the temporary cooldown.",
                user.id,
                status=429,
            )

    def failed_login(self, user: User | None) -> None:
        if user:
            now = time.time()
            # Update counters in SQL so concurrent attempts cannot lose increments.
            expired = User.failure_window_start < now - self.settings.rate_limit_window_seconds
            next_count = case((expired, 1), else_=User.failed_login_attempts + 1)
            self.db.execute(
                update(User)
                .where(User.id == user.id)
                .values(
                    failed_login_attempts=next_count,
                    failure_window_start=case((expired, now), else_=User.failure_window_start),
                    blocked_until=case(
                        (
                            next_count >= self.settings.login_failure_threshold,
                            now + self.settings.login_lock_seconds,
                        ),
                        else_=User.blocked_until,
                    ),
                )
                .execution_options(synchronize_session=False)
            )
            self.db.refresh(user)
            if user.failed_login_attempts >= self.settings.login_failure_threshold:
                self.events.record(
                    "BRUTE_FORCE_DETECTED",
                    "MEDIUM",
                    "Repeated failed logins triggered a temporary account cooldown.",
                    user.id,
                )
        self.events.record(
            "LOGIN_FAILED",
            "LOW",
            "Authentication credentials could not be verified.",
            user.id if user else None,
        )
        self.db.commit()

    def _issue(self, user: User) -> dict:
        user.failed_login_attempts, user.blocked_until, user.failure_window_start = 0, 0, 0
        token = secrets.token_urlsafe(32)
        expires = time.time() + self.settings.token_expiry_minutes * 60
        self.db.add(
            AuthToken(token_hash=crypto.sha256(token.encode()), user_id=user.id, expires_at=expires)
        )
        self.audit.record("LOGIN_SUCCESS", user.id, "user", user.id)
        self.events.record("LOGIN_SUCCESS", "INFO", "Authentication succeeded.", user.id)
        return {
            "access_token": token,
            "token_type": "bearer",
            "expires_at": expires,
            "user": user_view(user),
        }

    def login(self, data: Login) -> dict:
        user = self.repository.username(data.username)
        if user:
            self._blocked(user)
        try:
            PASSWORD_HASHER.verify(user.password_hash if user else DUMMY_HASH, data.password)
            if not user or not user.is_active:
                raise VerificationError("inactive")
        except (VerificationError, InvalidHashError) as exc:
            self.failed_login(user)
            raise AppError(
                "INVALID_CREDENTIALS", "Username or password is incorrect.", 401
            ) from exc
        if PASSWORD_HASHER.check_needs_rehash(user.password_hash):
            user.password_hash = PASSWORD_HASHER.hash(data.password)
        return self._issue(user)

    def challenge(self, username: str) -> dict:
        user = self.repository.username(username)
        if not user or not user.is_active:
            raise AppError(
                "CHALLENGE_UNAVAILABLE",
                "Challenge authentication is unavailable for this identity.",
                404,
            )
        self._blocked(user)
        challenge = AuthChallenge(
            user_id=user.id,
            challenge=secrets.token_hex(32),
            expires_at=time.time() + self.settings.challenge_expiry_seconds,
        )
        self.db.add(challenge)
        self.db.flush()
        self.audit.record("CHALLENGE_CREATED", user.id, "challenge", challenge.id)
        return {"id": challenge.id, "metadata": challenge_metadata(challenge)}

    def verify_challenge(self, data: ChallengeVerify) -> dict:
        challenge = self.db.get(AuthChallenge, str(data.challenge_id))
        if not challenge:
            raise AppError("CHALLENGE_NOT_FOUND", "Authentication challenge not found.", 404)
        user = self.repository.user(challenge.user_id)
        self._blocked(user)
        if challenge.used:
            self.events.reject(
                "REPLAY_ATTACK",
                "HIGH",
                "Authentication challenge has already been consumed.",
                user.id,
                status=409,
                code="CHALLENGE_REUSED",
            )
        if challenge.expires_at <= time.time():
            self.events.reject(
                "REPLAY_ATTACK",
                "HIGH",
                "Authentication challenge has expired.",
                user.id,
                code="CHALLENGE_EXPIRED",
            )
        if not crypto.verify(
            user.public_key_pem, data.signature, crypto.canonical(challenge_metadata(challenge))
        ):
            challenge.used = True
            self.failed_login(user)
            self.events.reject(
                "SIGNATURE_INVALID",
                "HIGH",
                "The authentication signature could not be verified.",
                user.id,
                code="SIGNATURE_VERIFICATION_FAILED",
            )
        changed = self.db.execute(
            update(AuthChallenge)
            .where(
                AuthChallenge.id == challenge.id,
                AuthChallenge.used.is_(False),
                AuthChallenge.expires_at > time.time(),
            )
            .values(used=True)
        ).rowcount
        if changed != 1:
            self.events.reject(
                "REPLAY_ATTACK",
                "HIGH",
                "The challenge was consumed concurrently or expired.",
                user.id,
                status=409,
                code="CHALLENGE_REUSED",
            )
        self.audit.record("CHALLENGE_VERIFIED", user.id, "challenge", challenge.id)
        return self._issue(user)
