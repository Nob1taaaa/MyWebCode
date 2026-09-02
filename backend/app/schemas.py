"""Request and response shapes. These never include hashed_password."""

from uuid import UUID

from pydantic import BaseModel, EmailStr, Field

from app.auth.permissions import Permission, Role


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)
    full_name: str = Field(min_length=1, max_length=120)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class RefreshRequest(BaseModel):
    refresh_token: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class UserPublic(BaseModel):
    id: UUID
    email: EmailStr
    full_name: str
    role: Role
    is_active: bool
    permissions: list[Permission]

    model_config = {"from_attributes": True}


class ProfileUpdate(BaseModel):
    full_name: str | None = Field(default=None, min_length=1, max_length=120)
