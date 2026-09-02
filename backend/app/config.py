"""
Application settings.

Secrets come from environment variables (or a local .env file).
Never commit real secrets. JWT_SECRET must be a long random string in production.
"""

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_name: str = "Auth API"
    database_url: str = "sqlite:///./auth.db"

    # Used to sign JWTs. Anyone with this value can mint valid tokens.
    jwt_secret: str = "change-me-in-production-use-a-long-random-string"
    jwt_algorithm: str = "HS256"

    # Access tokens are short-lived so a stolen token expires quickly.
    access_token_minutes: int = 15
    # Refresh tokens last longer so the user does not re-login every 15 minutes.
    refresh_token_days: int = 7


@lru_cache
def get_settings() -> Settings:
    return Settings()
