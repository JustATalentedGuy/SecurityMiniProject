from uuid import UUID

from fastapi import APIRouter, Depends

from app.api.dependencies import current_user, get_db
from app.repositories.repository import Repository
from app.services.user_service import UserService

router = APIRouter(
    prefix="/users", tags=["Identity registry"], dependencies=[Depends(current_user)]
)


@router.get("")
def users(db=Depends(get_db)):
    return UserService(Repository(db)).list()


@router.get("/{user_id}/public-key")
def public_key(user_id: UUID, db=Depends(get_db)):
    return UserService(Repository(db)).public_key(str(user_id))
