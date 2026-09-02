import os
from pathlib import Path

# Settings and the DB engine are created at import time. Set env first.
_TEST_DB = Path(__file__).resolve().parent / "test_auth.db"
os.environ["JWT_SECRET"] = "unit-test-secret-not-for-production"
os.environ["DATABASE_URL"] = f"sqlite:///{_TEST_DB}"
if _TEST_DB.exists():
    _TEST_DB.unlink()

import pytest
from fastapi.testclient import TestClient

from app.auth.permissions import Role
from app.database import Base, SessionLocal, engine
from app.main import app
from app.services.auth_service import get_user_by_email


@pytest.fixture
def client():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    with TestClient(app) as test_client:
        yield test_client
    Base.metadata.drop_all(bind=engine)


@pytest.fixture
def user_tokens(client: TestClient) -> dict:
    client.post(
        "/auth/register",
        json={
            "email": "ada@example.com",
            "password": "correct-horse",
            "full_name": "Ada Lovelace",
        },
    )
    response = client.post(
        "/auth/login",
        json={"email": "ada@example.com", "password": "correct-horse"},
    )
    assert response.status_code == 200
    return response.json()


@pytest.fixture
def admin_tokens(client: TestClient) -> dict:
    client.post(
        "/auth/register",
        json={
            "email": "admin@example.com",
            "password": "admin-pass-1",
            "full_name": "Admin",
        },
    )
    db = SessionLocal()
    try:
        admin = get_user_by_email(db, "admin@example.com")
        assert admin is not None
        admin.role = Role.ADMIN.value
        db.commit()
    finally:
        db.close()

    response = client.post(
        "/auth/login",
        json={"email": "admin@example.com", "password": "admin-pass-1"},
    )
    assert response.status_code == 200
    return response.json()


def auth_header(tokens: dict) -> dict:
    return {"Authorization": f"Bearer {tokens['access_token']}"}
