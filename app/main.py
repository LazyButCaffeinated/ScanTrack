from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

import app.models  # noqa: F401  (registers tables)
from app.api.v1.router import api_router
from app.core.config import get_settings
from app.db.base import Base
from app.db.session import engine

settings = get_settings()
is_prod = settings.app_env == "prod"


@asynccontextmanager
async def lifespan(_: FastAPI):
    Base.metadata.create_all(engine)  # swap for Alembic migrations when the schema starts changing
    yield


app = FastAPI(
    title="ScanTrack",
    version="1.0.0",
    lifespan=lifespan,
    docs_url=None if is_prod else "/docs",  # don't expose API docs in production
    redoc_url=None,
    openapi_url=None if is_prod else "/openapi.json",
)

if settings.cors_origins:
    app.add_middleware(
        CORSMiddleware, allow_origins=settings.cors_origins,
        allow_methods=["GET", "POST", "PATCH"], allow_headers=["Authorization", "Content-Type"],
    )


@app.middleware("http")
async def security_headers(request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    return response


@app.get("/health", tags=["meta"])
def health():
    return {"status": "ok"}


app.include_router(api_router)
