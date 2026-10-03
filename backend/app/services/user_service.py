from sqlalchemy import select

from app.core.crypto import fingerprint
from app.models import User
from app.repositories.repository import Repository


def user_view(user: User) -> dict:
    return {
        "id": user.id,
        "username": user.username,
        "public_key_pem": user.public_key_pem,
        "fingerprint": fingerprint(user.public_key_pem),
        "created_at": user.created_at,
    }


class UserService:
    def __init__(self, repository: Repository):
        self.repository = repository

    def list(self) -> list[dict]:
        return [
            user_view(user)
            for user in self.repository.db.scalars(
                select(User).where(User.is_active.is_(True)).order_by(User.username)
            )
        ]

    def public_key(self, user_id: str) -> dict:
        return user_view(self.repository.user(user_id))
