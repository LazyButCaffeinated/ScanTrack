from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import ANY_USER, get_db
from app.core.security import DUMMY_HASH, create_access_token, verify_password
from app.models.user import User
from app.schemas.user import Token, UserOut

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/login", response_model=Token)
def login(form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.scalar(select(User).where(User.username == form.username))
    # Always run one bcrypt check so response time doesn't reveal valid usernames.
    ok = verify_password(form.password, user.hashed_password if user else DUMMY_HASH)
    if not (user and ok and user.is_active):
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED, "Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return Token(access_token=create_access_token(user.username, user.role))


@router.get("/me", response_model=UserOut)
def me(user: User = ANY_USER):
    return user
