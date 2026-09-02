from tests.conftest import auth_header


def test_register_returns_public_user_without_password(client):
    response = client.post(
        "/auth/register",
        json={
            "email": "ada@example.com",
            "password": "correct-horse",
            "full_name": "Ada Lovelace",
        },
    )
    assert response.status_code == 201
    body = response.json()
    assert body["email"] == "ada@example.com"
    assert body["role"] == "user"
    assert "hashed_password" not in body
    assert "password" not in body
    assert "read:own_profile" in body["permissions"]
    assert "read:users" not in body["permissions"]


def test_register_rejects_duplicate_email(client):
    payload = {
        "email": "ada@example.com",
        "password": "correct-horse",
        "full_name": "Ada",
    }
    assert client.post("/auth/register", json=payload).status_code == 201
    again = client.post("/auth/register", json=payload)
    assert again.status_code == 409


def test_register_rejects_short_password(client):
    response = client.post(
        "/auth/register",
        json={"email": "ada@example.com", "password": "short", "full_name": "Ada"},
    )
    assert response.status_code == 422


def test_login_success_and_failure(client):
    client.post(
        "/auth/register",
        json={
            "email": "ada@example.com",
            "password": "correct-horse",
            "full_name": "Ada",
        },
    )
    ok = client.post(
        "/auth/login",
        json={"email": "ada@example.com", "password": "correct-horse"},
    )
    assert ok.status_code == 200
    assert ok.json()["token_type"] == "bearer"
    assert ok.json()["access_token"]
    assert ok.json()["refresh_token"]

    bad = client.post(
        "/auth/login",
        json={"email": "ada@example.com", "password": "wrong-password"},
    )
    assert bad.status_code == 401
    assert bad.json()["detail"] == "Invalid email or password"

    missing = client.post(
        "/auth/login",
        json={"email": "nobody@example.com", "password": "correct-horse"},
    )
    assert missing.status_code == 401


def test_me_requires_access_token(client, user_tokens):
    assert client.get("/me").status_code == 401
    me = client.get("/me", headers=auth_header(user_tokens))
    assert me.status_code == 200
    assert me.json()["email"] == "ada@example.com"


def test_refresh_issues_new_tokens(client, user_tokens):
    response = client.post(
        "/auth/refresh",
        json={"refresh_token": user_tokens["refresh_token"]},
    )
    assert response.status_code == 200
    new_tokens = response.json()
    me = client.get("/me", headers=auth_header(new_tokens))
    assert me.status_code == 200

    # An access token cannot be used as a refresh token.
    misuse = client.post(
        "/auth/refresh",
        json={"refresh_token": user_tokens["access_token"]},
    )
    assert misuse.status_code == 401


def test_user_cannot_list_users_admin_can(client, user_tokens, admin_tokens):
    forbidden = client.get("/users", headers=auth_header(user_tokens))
    assert forbidden.status_code == 403
    assert "read:users" in forbidden.json()["detail"]

    allowed = client.get("/users", headers=auth_header(admin_tokens))
    assert allowed.status_code == 200
    emails = {row["email"] for row in allowed.json()}
    assert "ada@example.com" in emails
    assert "admin@example.com" in emails


def test_admin_can_disable_user_then_user_cannot_login(client, user_tokens, admin_tokens):
    users = client.get("/users", headers=auth_header(admin_tokens)).json()
    ada = next(u for u in users if u["email"] == "ada@example.com")

    disable = client.delete(f"/users/{ada['id']}", headers=auth_header(admin_tokens))
    assert disable.status_code == 204

    still_authed = client.get("/me", headers=auth_header(user_tokens))
    assert still_authed.status_code == 401

    login = client.post(
        "/auth/login",
        json={"email": "ada@example.com", "password": "correct-horse"},
    )
    assert login.status_code == 403


def test_update_own_profile(client, user_tokens):
    response = client.patch(
        "/me",
        headers=auth_header(user_tokens),
        json={"full_name": "Ada L."},
    )
    assert response.status_code == 200
    assert response.json()["full_name"] == "Ada L."
