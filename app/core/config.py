"""All configuration comes from environment variables (12-factor). No secrets in code."""
from functools import lru_cache

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_env: str = "dev"  # dev | prod
    database_url: str = "sqlite:///./data/scantrack.db"
    secret_key: str  # REQUIRED - app refuses to start without it
    jwt_algorithm: str = "HS256"
    access_token_minutes: int = 30
    cors_origins: list[str] = []  # empty = CORS disabled

    @field_validator("secret_key")
    @classmethod
    def _strong_secret(cls, v: str) -> str:
        if len(v) < 32:
            raise ValueError("SECRET_KEY must be at least 32 characters")
        return v


@lru_cache
def get_settings() -> Settings:
    return Settings()
