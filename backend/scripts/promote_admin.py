"""
Promote an existing account to admin (grants READ_USERS and DELETE_USERS).

    python scripts/promote_admin.py you@example.com
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.auth.permissions import Role  # noqa: E402
from app.database import SessionLocal  # noqa: E402
from app.services.auth_service import get_user_by_email  # noqa: E402


def main() -> int:
    if len(sys.argv) != 2:
        print("Usage: python scripts/promote_admin.py <email>")
        return 1

    email = sys.argv[1]
    db = SessionLocal()
    try:
        user = get_user_by_email(db, email)
        if user is None:
            print(f"No user with email {email}")
            return 1
        user.role = Role.ADMIN.value
        db.commit()
        print(f"{email} is now an admin")
        return 0
    finally:
        db.close()


if __name__ == "__main__":
    raise SystemExit(main())
