"""
Authentication vs authorization API.

Authentication  = prove who you are  (login → JWT)
Authorization   = check what you may do (role → permissions)

Typical client flow:
  1. POST /auth/register
  2. POST /auth/login          → access_token + refresh_token
  3. GET  /me                  Authorization: Bearer <access_token>
  4. POST /auth/refresh        when the access token expires
"""

from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.config import get_settings
from app.database import Base, engine
from app.routers import auth, users


@asynccontextmanager
async def lifespan(_: FastAPI):
    Base.metadata.create_all(bind=engine)
    yield


def create_app() -> FastAPI:
    settings = get_settings()
    application = FastAPI(
        title=settings.app_name,
        description=__doc__,
        lifespan=lifespan,
    )
    application.include_router(auth.router)
    application.include_router(users.router)
    return application


app = create_app()
