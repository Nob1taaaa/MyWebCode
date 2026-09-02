"""
FastAPI dependencies: load the current user and enforce permissions.

Routes stay thin:
    @router.get("/me")
    def me(user: User = Depends(get_current_user)): ...

    @router.get("/users")
    def list_users(user: User = Depends(require_permission(Permission.READ_USERS))): ...
"""

from typing import Annotated, Callable

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.auth.permissions import Permission, has_permission
from app.auth.tokens import TokenError, decode_token
from app.database import get_db
from app.models.user import User
from app.services import auth_service

bearer_scheme = HTTPBearer(auto_error=False)


def get_current_user(
    creds: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)],
    db: Annotated[Session, Depends(get_db)],
) -> User:
    """Authentication gate: valid access JWT → User, otherwise 401."""
    if creds is None or creds.scheme.lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        user_id = decode_token(creds.credentials, "access")
    except TokenError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    user = auth_service.get_user_by_id(db, user_id)
    if user is None or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or disabled",
        )
    return user


def require_permission(permission: Permission) -> Callable[..., User]:
    """Authorization gate: current user must hold this permission, else 403."""

    def _checker(user: Annotated[User, Depends(get_current_user)]) -> User:
        if not has_permission(user.role_enum, permission):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Missing permission: {permission.value}",
            )
        return user

    return _checker
