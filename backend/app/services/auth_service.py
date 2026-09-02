"""Register, login, and token refresh — the authentication service."""

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth.passwords import hash_password, verify_password
from app.auth.permissions import Role, permissions_for
from app.auth.tokens import TokenError, create_token, decode_token
from app.models.user import User
from app.schemas import UserPublic


class AuthError(Exception):
    def __init__(self, status_code: int, detail: str) -> None:
        self.status_code = status_code
        self.detail = detail
        super().__init__(detail)


def to_public(user: User) -> UserPublic:
    return UserPublic(
        id=user.id,
        email=user.email,
        full_name=user.full_name,
        role=user.role_enum,
        is_active=user.is_active,
        permissions=sorted(permissions_for(user.role_enum), key=lambda p: p.value),
    )


def get_user_by_email(db: Session, email: str) -> User | None:
    return db.scalar(select(User).where(User.email == email.lower()))


def get_user_by_id(db: Session, user_id: UUID) -> User | None:
    return db.get(User, user_id)


def register_user(db: Session, email: str, password: str, full_name: str) -> User:
    if get_user_by_email(db, email):
        raise AuthError(409, "An account with this email already exists")

    user = User(
        email=email.lower(),
        hashed_password=hash_password(password),
        full_name=full_name,
        role=Role.USER.value,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


# Precomputed so missing-user logins still run bcrypt without hashing on every request.
_DUMMY_HASH = hash_password("dummy-password-for-timing")


def authenticate(db: Session, email: str, password: str) -> User:
    """
    Verify identity. Always run password verification even if the user is
    missing, so timing does not leak whether an email is registered.
    """
    user = get_user_by_email(db, email)
    hashed = user.hashed_password if user else _DUMMY_HASH
    password_ok = verify_password(password, hashed)

    if not user or not password_ok:
        raise AuthError(401, "Invalid email or password")
    if not user.is_active:
        raise AuthError(403, "Account is disabled")
    return user


def issue_tokens(user: User) -> dict[str, str]:
    return {
        "access_token": create_token(user.id, "access"),
        "refresh_token": create_token(user.id, "refresh"),
        "token_type": "bearer",
    }


def refresh_access_token(db: Session, refresh_token: str) -> dict[str, str]:
    try:
        user_id = decode_token(refresh_token, "refresh")
    except TokenError as exc:
        raise AuthError(401, str(exc)) from exc

    user = get_user_by_id(db, user_id)
    if not user or not user.is_active:
        raise AuthError(401, "Invalid refresh token")
    return issue_tokens(user)
