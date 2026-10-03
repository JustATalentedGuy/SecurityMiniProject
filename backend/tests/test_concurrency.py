import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor

from app.models import User
from app.services.audit_service import AuditService
from app.services.auth_service import AuthService
from app.services.security_event_service import SecurityEventService


def test_concurrent_authentication_failures_preserve_all_increments(client, identities, app):
    user_id = identities["alice"]["user"]["id"]
    barrier = threading.Barrier(5)

    def fail(_index):
        with app.state.database() as db:
            user = db.get(User, user_id)
            barrier.wait(timeout=5)  # all workers start from the same stale zero-count identity
            request_id = str(uuid.uuid4())
            events = SecurityEventService(db, request_id, "test")
            audit = AuditService(db, request_id)
            AuthService(db, app.state.settings, events, audit).failed_login(user)

    with ThreadPoolExecutor(max_workers=5) as pool:
        list(pool.map(fail, range(5)))
    with app.state.database() as db:
        user = db.get(User, user_id)
        assert user.failed_login_attempts == 5
        assert user.blocked_until > time.time()
