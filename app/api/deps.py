"""Shared FastAPI dependencies: DB session, current user, role guard."""
from collections.abc import Generator

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.security import decode_access_token
from app.db.session import SessionLocal
from app.models.user import User
from app.schemas.enums import Role

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> User:
    unauthorized = HTTPException(
        status.HTTP_401_UNAUTHORIZED, "Invalid or expired token",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        claims = decode_access_token(token)
    except jwt.PyJWTError:
        raise unauthorized
    # Re-check the DB every request so disabled users / role changes apply immediately.
    user = db.scalar(select(User).where(User.username == claims["sub"]))
    if user is None or not user.is_active:
        raise unauthorized
    return user


def require_role(*roles: Role):
    allowed = {r.value for r in roles}

    def checker(user: User = Depends(get_current_user)) -> User:
        if user.role not in allowed:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Insufficient permissions")
        return user

    return checker


ANY_USER = Depends(get_current_user)
ANALYST_UP = Depends(require_role(Role.admin, Role.analyst))
ADMIN_ONLY = Depends(require_role(Role.admin))
