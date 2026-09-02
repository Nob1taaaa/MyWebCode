"""
Password hashing.

Authentication starts with a secret the user knows (their password).
We never store that password. We store a one-way bcrypt hash.

bcrypt automatically:
  - salts each hash (same password → different stored value)
  - is slow on purpose, which makes brute-force guessing expensive
"""

import bcrypt


def hash_password(plain: str) -> str:
    hashed = bcrypt.hashpw(plain.encode("utf-8"), bcrypt.gensalt())
    return hashed.decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))
