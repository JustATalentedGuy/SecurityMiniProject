from fastapi import APIRouter, Depends, Request

from app.api.dependencies import bearer, current_user, rate_limit, services
from app.core.crypto import sha256
from app.models import AuthToken
from app.schemas import ChallengeRequest, ChallengeVerify, Login, Register
from app.services.auth_service import AuthService
from app.services.user_service import user_view

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post("/register", status_code=201, dependencies=[Depends(rate_limit("register"))])
def register(data: Register, svc=Depends(services)):
    return AuthService(*svc).register(data)


@router.post("/login", dependencies=[Depends(rate_limit("login"))])
def login(data: Login, svc=Depends(services)):
    return AuthService(*svc).login(data)


@router.post("/challenge", dependencies=[Depends(rate_limit("challenge"))])
def challenge(data: ChallengeRequest, svc=Depends(services)):
    return AuthService(*svc).challenge(data.username)


@router.post("/challenge/verify", dependencies=[Depends(rate_limit("verify"))])
def verify_challenge(data: ChallengeVerify, svc=Depends(services)):
    return AuthService(*svc).verify_challenge(data)


@router.get("/me")
def me(user=Depends(current_user)):
    return user_view(user)


@router.post("/logout", status_code=204)
def logout(
    request: Request, user=Depends(current_user), credentials=Depends(bearer), svc=Depends(services)
):
    db, _settings, _events, audit = svc
    db.delete(db.get(AuthToken, sha256(credentials.credentials.encode())))
    audit.record("LOGOUT", user.id, "user", user.id)
