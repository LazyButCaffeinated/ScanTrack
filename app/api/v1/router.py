from fastapi import APIRouter

from app.api.v1 import auth, findings, ingest, users

api_router = APIRouter(prefix="/api/v1")
for r in (auth.router, users.router, ingest.router, findings.router):
    api_router.include_router(r)
