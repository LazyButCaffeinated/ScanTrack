from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.schemas.enums import Severity, Status


class FindingIn(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)
    asset: str = Field(min_length=1, max_length=255)
    plugin_id: str = Field(min_length=1, max_length=100)
    title: str = Field(min_length=1, max_length=500)
    severity: Severity
    cve: str | None = Field(default=None, max_length=32)
    description: str | None = Field(default=None, max_length=5000)


class IngestRequest(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)
    scanner: str = Field(min_length=1, max_length=50)
    findings: list[FindingIn] = Field(max_length=5000)  # cap payload size


class IngestResult(BaseModel):
    received: int  # after de-duplicating inside the payload
    created: int
    updated: int
    reopened: int


class FindingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    scanner: str
    asset: str
    plugin_id: str
    title: str
    severity: Severity
    status: Status
    cve: str | None
    description: str | None
    first_seen: datetime
    last_seen: datetime
    fixed_at: datetime | None


class FindingPage(BaseModel):
    items: list[FindingOut]
    total: int
    limit: int
    offset: int


class StatusUpdate(BaseModel):
    status: Status
