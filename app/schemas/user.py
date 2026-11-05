from pydantic import BaseModel, ConfigDict, Field

from app.schemas.enums import Role


class UserCreate(BaseModel):
    username: str = Field(pattern=r"^[A-Za-z0-9_.-]{3,32}$")
    password: str = Field(min_length=12, max_length=64)  # bcrypt caps at 72 bytes
    role: Role = Role.viewer


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    username: str
    role: Role
    is_active: bool


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
