from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.exceptions import AppError
from app.models import Transfer, User


class Repository:
    def __init__(self, db: Session):
        self.db = db

    def user(self, user_id: str) -> User:
        user = self.db.get(User, user_id)
        if not user or not user.is_active:
            raise AppError("USER_NOT_FOUND", "The selected user is unavailable.", 404)
        return user

    def username(self, username: str) -> User | None:
        return self.db.scalar(select(User).where(User.username == username.lower()))

    def transfer(self, transfer_id: str, actor: User) -> Transfer:
        transfer = self.db.get(Transfer, transfer_id)
        if not transfer or actor.id not in (transfer.sender_id, transfer.receiver_id):
            raise AppError("TRANSFER_NOT_FOUND", "Transfer not found or inaccessible.", 404)
        return transfer
