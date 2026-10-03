from uuid import UUID

from fastapi import APIRouter, Depends, Request

from app.api.dependencies import current_user, rate_limit, services
from app.services.demo_service import DemoService

router = APIRouter(
    prefix="/demo",
    tags=["Isolated attack demonstrations"],
    dependencies=[Depends(rate_limit("demo"))],
)


def service(request: Request, svc=Depends(services)):
    db, settings, events, audit = svc
    return DemoService(db, settings, request.app.state.storage, events, audit)


@router.post("/transfers/{transfer_id}/tamper")
def tamper(transfer_id: UUID, user=Depends(current_user), demo=Depends(service)):
    return demo.corrupt(user, str(transfer_id), False)


@router.post("/transfers/{transfer_id}/signature")
def signature(transfer_id: UUID, user=Depends(current_user), demo=Depends(service)):
    return demo.corrupt(user, str(transfer_id), True)


@router.post("/transfers/{transfer_id}/replay")
def replay(transfer_id: UUID, user=Depends(current_user), demo=Depends(service)):
    return demo.replay(user, str(transfer_id))


@router.post("/mitm/plain")
def plain_mitm(user=Depends(current_user), demo=Depends(service)):
    return demo.mitm(user, False)


@router.post("/mitm/authenticated")
def authenticated_mitm(user=Depends(current_user), demo=Depends(service)):
    return demo.mitm(user, True)


@router.post("/brute-force")
def brute_force(user=Depends(current_user), demo=Depends(service)):
    return demo.brute_force(user)


@router.post("/reset-cooldown")
def reset_cooldown(user=Depends(current_user), demo=Depends(service)):
    return demo.reset_cooldown(user)
