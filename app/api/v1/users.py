from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import ADMIN_ONLY, get_db
from app.core.security import hash_password
from app.models.user import User
from app.schemas.user import UserCreate, UserOut

router = APIRouter(prefix="/users", tags=["users"], dependencies=[ADMIN_ONLY])


@router.post("", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def create_user(body: UserCreate, db: Session = Depends(get_db)):
    if db.scalar(select(User).where(User.username == body.username)):
        raise HTTPException(status.HTTP_409_CONFLICT, "Username already exists")
    user = User(username=body.username, hashed_password=hash_password(body.password), role=body.role.value)
    db.add(user)
    db.commit()
    return user
