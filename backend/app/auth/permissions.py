"""
Roles and permissions.

Authorization answers: "is this authenticated user allowed to do this?"

This project uses Role-Based Access Control (RBAC):
  1. Each user has one role (user or admin).
  2. Each role maps to a set of permissions.
  3. Endpoints require a permission (or a role) via FastAPI dependencies.

Why not check role names everywhere?
  Checking `role == admin` in every route becomes rigid. Permissions stay
  stable ("can_read_users") even if you later add a "moderator" role.
"""

from enum import Enum


class Role(str, Enum):
    USER = "user"
    ADMIN = "admin"


class Permission(str, Enum):
    READ_OWN_PROFILE = "read:own_profile"
    UPDATE_OWN_PROFILE = "update:own_profile"
    READ_USERS = "read:users"
    DELETE_USERS = "delete:users"


ROLE_PERMISSIONS: dict[Role, set[Permission]] = {
    Role.USER: {
        Permission.READ_OWN_PROFILE,
        Permission.UPDATE_OWN_PROFILE,
    },
    Role.ADMIN: {
        Permission.READ_OWN_PROFILE,
        Permission.UPDATE_OWN_PROFILE,
        Permission.READ_USERS,
        Permission.DELETE_USERS,
    },
}


def permissions_for(role: Role) -> set[Permission]:
    return ROLE_PERMISSIONS[role]


def has_permission(role: Role, permission: Permission) -> bool:
    return permission in ROLE_PERMISSIONS[role]
