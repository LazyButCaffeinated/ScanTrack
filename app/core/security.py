"""Password hashing + JWT helpers. Pure functions, no DB or FastAPI here."""
from datetime import datetime, timedelta, timezone

import bcrypt
import jwt

from app.core.config import get_settings


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode()


def verify_password(password: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode(), hashed.encode())
    except ValueError:
        return False


# Used to burn the same CPU time when a username doesn't exist (anti user-enumeration).
DUMMY_HASH = hash_password("not-a-real-password")


def create_access_token(subject: str, role: str, expires_delta: timedelta | None = None) -> str:
    s = get_settings()
    now = datetime.now(timezone.utc)
    exp = now + (expires_delta or timedelta(minutes=s.access_token_minutes))
    payload = {"sub": subject, "role": role, "iat": now, "exp": exp}
    return jwt.encode(payload, s.secret_key, algorithm=s.jwt_algorithm)


def decode_access_token(token: str) -> dict:
    """Raises jwt.PyJWTError on any problem (bad signature, expired, malformed)."""
    s = get_settings()
    return jwt.decode(
        token,
        s.secret_key,
        algorithms=[s.jwt_algorithm],  # pin the algorithm - never trust the token header
        options={"require": ["exp", "sub"]},
    )
