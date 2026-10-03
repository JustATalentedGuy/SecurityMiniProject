import base64
import json
from uuid import UUID

from fastapi import APIRouter, Depends, Header, Request, Response

from app.api.dependencies import current_user, rate_limit, services
from app.core.exceptions import AppError
from app.schemas import SignedOperation, TransferCreate
from app.services.transfer_service import TransferService

router = APIRouter(prefix="/transfers", tags=["Encrypted transfers"])


def service(request: Request, svc=Depends(services)):
    db, settings, events, audit = svc
    return TransferService(db, settings, request.app.state.storage, events, audit)


@router.post("", status_code=201, dependencies=[Depends(rate_limit("upload"))])
def create(
    data: TransferCreate,
    idempotency_key: UUID = Header(),
    user=Depends(current_user),
    transfer_service=Depends(service),
):
    return transfer_service.create(user, data, str(idempotency_key))


@router.get("/sent")
def sent(user=Depends(current_user), transfer_service=Depends(service)):
    return transfer_service.list(user, False)


@router.get("/received")
def received(user=Depends(current_user), transfer_service=Depends(service)):
    return transfer_service.list(user, True)


@router.get("/stats")
def stats(user=Depends(current_user), transfer_service=Depends(service)):
    return transfer_service.stats(user)


@router.get("/{transfer_id}")
def detail(transfer_id: UUID, user=Depends(current_user), transfer_service=Depends(service)):
    return transfer_service.detail(user, str(transfer_id))


@router.post("/{transfer_id}/upload", dependencies=[Depends(rate_limit("upload"))])
async def upload(
    transfer_id: UUID,
    request: Request,
    x_transfer_metadata: str = Header(max_length=8192),
    x_transfer_signature: str = Header(min_length=100, max_length=800),
    user=Depends(current_user),
    transfer_service=Depends(service),
):
    if request.headers.get("content-type", "").split(";")[0] != "application/octet-stream":
        raise AppError(
            "INVALID_CONTENT_TYPE", "Send only ciphertext as application/octet-stream.", 415
        )
    try:
        metadata = json.loads(base64.b64decode(x_transfer_metadata, validate=True))
    except (ValueError, UnicodeError) as exc:
        raise AppError("INVALID_METADATA", "Upload metadata must be base64-encoded JSON.") from exc
    operation = SignedOperation(metadata=metadata, signature=x_transfer_signature)
    ciphertext = bytearray()
    async for chunk in request.stream():
        ciphertext.extend(chunk)
        if len(ciphertext) > transfer_service.settings.max_upload_bytes + 16:
            transfer_service.events.reject(
                "UPLOAD_LIMIT_EXCEEDED",
                "MEDIUM",
                "Upload stream exceeds the size limit.",
                user.id,
                str(transfer_id),
                413,
            )
    return transfer_service.upload(user, str(transfer_id), bytes(ciphertext), operation)


@router.get("/{transfer_id}/download")
def download(transfer_id: UUID, user=Depends(current_user), transfer_service=Depends(service)):
    return Response(
        transfer_service.download(user, str(transfer_id)),
        media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{transfer_id}.enc"'},
    )


@router.post("/{transfer_id}/verify", dependencies=[Depends(rate_limit("verify"))])
def verify_transfer(
    transfer_id: UUID,
    data: SignedOperation,
    user=Depends(current_user),
    transfer_service=Depends(service),
):
    return transfer_service.verify(user, str(transfer_id), data)
