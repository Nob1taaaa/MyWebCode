"""
JSON Web Tokens (JWTs).

After login we do not keep server-side sessions. We issue a signed token.
The client sends it on later requests: Authorization: Bearer <token>

A JWT has three parts: header.payload.signature
  - payload holds claims (sub = user id, type = access|refresh, exp)
  - signature is HMAC-SHA256 with JWT_SECRET

Access token: short life, used on every API call.
Refresh token: longer life, used only to mint a new access token.
If an access token leaks, damage is limited to its short expiry.
"""

from datetime import datetime, timedelta, timezone
from typing import Literal
from uuid import UUID

import jwt

from app.config import get_settings

TokenType = Literal["access", "refresh"]


class TokenError(Exception):
    pass


def _now() -> datetime:
    return datetime.now(timezone.utc)


def create_token(user_id: UUID, token_type: TokenType) -> str:
    settings = get_settings()
    if token_type == "access":
        ttl = timedelta(minutes=settings.access_token_minutes)
    else:
        ttl = timedelta(days=settings.refresh_token_days)

    payload = {
        "sub": str(user_id),
        "type": token_type,
        "iat": _now(),
        "exp": _now() + ttl,
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)


def decode_token(token: str, expected_type: TokenType) -> UUID:
    settings = get_settings()
    try:
        payload = jwt.decode(
            token,
            settings.jwt_secret,
            algorithms=[settings.jwt_algorithm],
        )
    except jwt.ExpiredSignatureError as exc:
        raise TokenError("Token has expired") from exc
    except jwt.InvalidTokenError as exc:
        raise TokenError("Invalid token") from exc

    if payload.get("type") != expected_type:
        raise TokenError(f"Expected a {expected_type} token")

    try:
        return UUID(payload["sub"])
    except (KeyError, ValueError) as exc:
        raise TokenError("Token is missing a valid subject") from exc
