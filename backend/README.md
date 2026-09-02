# Authentication and authorization backend

This API is a small, readable example of two problems that are easy to mix up:

| Question | Name | This project’s answer |
| --- | --- | --- |
| Who are you? | **Authentication** | Email + password → signed JWT |
| What may you do? | **Authorization** | Role → permissions → route dependencies |

You can run the server, call the routes, and read the code in that same order.

## How a request is allowed through

```
Client
  │  Authorization: Bearer <access_token>
  ▼
get_current_user          AUTHENTICATION
  │  decode JWT (signature + expiry + type=access)
  │  load User from the database
  │  401 if missing / expired / inactive
  ▼
require_permission(...)   AUTHORIZATION
  │  look up role → permission set
  │  403 if the permission is missing
  ▼
Route handler
```

A **401** means “we do not know who you are.”
A **403** means “we know who you are, and you are not allowed.”

## Tokens (stateless sessions)

After `POST /auth/login` the server does not store a session. It returns two JWTs:

- **Access token** (15 minutes): sent on every API call.
- **Refresh token** (7 days): sent only to `POST /auth/refresh` to mint a new pair.

JWTs are signed with `JWT_SECRET`. Anyone who has that secret can forge tokens, so it must be a long random value in production.

Passwords are never stored. `bcrypt` hashes them with a unique salt (`app/auth/passwords.py`).

## Roles and permissions (RBAC)

New accounts get role `user`. Admins are promoted in the database (see below).

| Permission | `user` | `admin` |
| --- | --- | --- |
| `read:own_profile` | yes | yes |
| `update:own_profile` | yes | yes |
| `read:users` | no | yes |
| `delete:users` | no | yes |

Routes ask for a **permission**, not a role name. That way a future `moderator` role can reuse `read:users` without rewriting every handler. Mapping lives in `app/auth/permissions.py`.

## Project layout

```
backend/
  app/
    main.py                 FastAPI app
    config.py               env settings
    database.py             SQLAlchemy session
    schemas.py              request/response models (never include password hashes)
    deps.py                 get_current_user + require_permission
    auth/
      passwords.py          bcrypt hash / verify
      tokens.py             create / decode JWT
      permissions.py        Role, Permission, RBAC map
    models/user.py          User table
    services/auth_service.py register, login, refresh
    routers/auth.py         /auth/register, /login, /refresh
    routers/users.py        /me, /users
  scripts/promote_admin.py
  tests/                    pytest coverage of the flow above
```

## Run locally

```bash
cd backend
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
uvicorn app.main:app --reload --port 8000
```

Open http://localhost:8000/docs for the interactive OpenAPI UI.

### Try the flow

```bash
# 1. Register (authentication identity is created; role is user)
curl -s -X POST http://localhost:8000/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"email":"ada@example.com","password":"correct-horse","full_name":"Ada"}'

# 2. Login → tokens
curl -s -X POST http://localhost:8000/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"ada@example.com","password":"correct-horse"}'

# 3. Call a protected route (paste the access_token)
curl -s http://localhost:8000/me \
  -H "Authorization: Bearer ACCESS_TOKEN"

# 4. This fails with 403 for a normal user
curl -s http://localhost:8000/users \
  -H "Authorization: Bearer ACCESS_TOKEN"
```

Promote a user to admin (authorization changes, identity stays the same):

```bash
python scripts/promote_admin.py ada@example.com
```

Log in again so the new role is loaded, then `GET /users` succeeds.

## Tests

```bash
cd backend
pytest -q
```

## Production notes (not implemented here on purpose)

- Put `JWT_SECRET` in a real secret manager; never ship the default.
- Use PostgreSQL instead of SQLite.
- Store refresh tokens (or a token family) so they can be revoked on logout.
- Add rate limits on `/auth/login` and `/auth/register`.
- Serve the API over HTTPS only.
