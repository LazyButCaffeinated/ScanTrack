"""Create the first admin. Prompts for the password so it never lands in shell history.
Usage:  python -m scripts.create_admin
"""
import getpass
import sys

from sqlalchemy import select

import app.models  # noqa: F401
from app.core.security import hash_password
from app.db.base import Base
from app.db.session import SessionLocal, engine
from app.models.user import User


def main() -> None:
    Base.metadata.create_all(engine)
    username = input("Admin username: ").strip()
    password = getpass.getpass("Password (min 12 chars): ")
    if len(password) < 12 or len(password) > 64:
        sys.exit("Password must be 12-64 characters.")
    with SessionLocal() as db:
        if db.scalar(select(User).where(User.username == username)):
            sys.exit("User already exists.")
        db.add(User(username=username, hashed_password=hash_password(password), role="admin"))
        db.commit()
    print(f"Admin '{username}' created.")


if __name__ == "__main__":
    main()
