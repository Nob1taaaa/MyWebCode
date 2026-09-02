"""Public auth routes: register, login, refresh. No token required."""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database import get_db
from app.schemas import LoginRequest, RefreshRequest, RegisterRequest, TokenResponse, UserPublic
from app.services import auth_service
from app.services.auth_service import AuthError

router = APIRouter(prefix="/auth", tags=["auth"])


def _raise(exc: AuthError) -> None:
    raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc


@router.post("/register", response_model=UserPublic, status_code=201)
def register(body: RegisterRequest, db: Annotated[Session, Depends(get_db)]) -> UserPublic:
    try:
        user = auth_service.register_user(db, body.email, body.password, body.full_name)
    except AuthError as exc:
        _raise(exc)
    return auth_service.to_public(user)


@router.post("/login", response_model=TokenResponse)
def login(body: LoginRequest, db: Annotated[Session, Depends(get_db)]) -> dict:
    try:
        user = auth_service.authenticate(db, body.email, body.password)
    except AuthError as exc:
        _raise(exc)
    return auth_service.issue_tokens(user)


@router.post("/refresh", response_model=TokenResponse)
def refresh(body: RefreshRequest, db: Annotated[Session, Depends(get_db)]) -> dict:
    try:
        return auth_service.refresh_access_token(db, body.refresh_token)
    except AuthError as exc:
        _raise(exc)
