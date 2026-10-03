from uuid import UUID

from fastapi import APIRouter, Depends

from app.api.dependencies import current_user, rate_limit, services
from app.schemas import SignedOperation
from app.services.session_service import SessionService, session_view

router = APIRouter(prefix="/sessions", tags=["Authenticated key exchange"])


@router.get("")
def list_sessions(user=Depends(current_user), svc=Depends(services)):
    return SessionService(*svc).list(user)


@router.post("/initiate", dependencies=[Depends(rate_limit("verify"))])
def initiate(data: SignedOperation, user=Depends(current_user), svc=Depends(services)):
    return SessionService(*svc).initiate(user, data)


@router.get("/{session_id}")
def get_session(session_id: UUID, user=Depends(current_user), svc=Depends(services)):
    session, _transfer = SessionService(*svc).get(str(session_id), user)
    return session_view(session)


@router.post("/{session_id}/respond", dependencies=[Depends(rate_limit("verify"))])
def respond(
    session_id: UUID, data: SignedOperation, user=Depends(current_user), svc=Depends(services)
):
    return SessionService(*svc).respond(str(session_id), user, data)


@router.post("/{session_id}/verify", dependencies=[Depends(rate_limit("verify"))])
def verify_session(
    session_id: UUID, data: SignedOperation, user=Depends(current_user), svc=Depends(services)
):
    return SessionService(*svc).verify(str(session_id), user, data)
