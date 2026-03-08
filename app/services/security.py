import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

import bcrypt
import jwt

from ..settings import API_JWT_ALGO, API_JWT_SECRET, API_TOKEN_EXPIRE_MINUTES


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))
    except ValueError:
        return False


def create_access_token(subject: str, role: str, organization_id: int | None) -> str:
    now = datetime.now(timezone.utc)
    payload: dict[str, Any] = {
        "sub": subject,
        "role": role,
        "org": organization_id,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=API_TOKEN_EXPIRE_MINUTES)).timestamp()),
    }
    return jwt.encode(payload, API_JWT_SECRET, algorithm=API_JWT_ALGO)


def decode_access_token(token: str) -> dict[str, Any]:
    return jwt.decode(token, API_JWT_SECRET, algorithms=[API_JWT_ALGO])


def generate_otp() -> str:
    return "".join(secrets.choice("0123456789") for _ in range(6))


def generate_token(length: int = 48) -> str:
    return secrets.token_urlsafe(length)


def hash_token(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()

