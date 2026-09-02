"""Authenticated user routes and admin-only user management."""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth.permissions import Permission
from app.database import get_db
from app.deps import get_current_user, require_permission
from app.models.user import User
from app.schemas import ProfileUpdate, UserPublic
from app.services import auth_service

router = APIRouter(tags=["users"])


@router.get("/me", response_model=UserPublic)
def read_me(user: Annotated[User, Depends(get_current_user)]) -> UserPublic:
    return auth_service.to_public(user)


@router.patch("/me", response_model=UserPublic)
def update_me(
    body: ProfileUpdate,
    user: Annotated[User, Depends(require_permission(Permission.UPDATE_OWN_PROFILE))],
    db: Annotated[Session, Depends(get_db)],
) -> UserPublic:
    if body.full_name is not None:
        user.full_name = body.full_name
        db.commit()
        db.refresh(user)
    return auth_service.to_public(user)


@router.get("/users", response_model=list[UserPublic])
def list_users(
    _: Annotated[User, Depends(require_permission(Permission.READ_USERS))],
    db: Annotated[Session, Depends(get_db)],
) -> list[UserPublic]:
    users = db.scalars(select(User).order_by(User.created_at)).all()
    return [auth_service.to_public(u) for u in users]


@router.delete("/users/{user_id}", status_code=204)
def disable_user(
    user_id: UUID,
    actor: Annotated[User, Depends(require_permission(Permission.DELETE_USERS))],
    db: Annotated[Session, Depends(get_db)],
) -> None:
    target = auth_service.get_user_by_id(db, user_id)
    if target is None:
        raise HTTPException(status_code=404, detail="User not found")
    if target.id == actor.id:
        raise HTTPException(status_code=400, detail="You cannot disable your own account")
    target.is_active = False
    db.commit()
