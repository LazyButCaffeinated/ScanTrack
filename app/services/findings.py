"""Business logic: querying findings and the open -> fixed lifecycle."""
from datetime import datetime, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.finding import Finding
from app.schemas.enums import Severity, Status

# Allowed lifecycle moves. Anything else is rejected.
TRANSITIONS: dict[Status, set[Status]] = {
    Status.open: {Status.in_progress, Status.fixed},
    Status.in_progress: {Status.open, Status.fixed},
    Status.fixed: {Status.open},
}


class InvalidTransition(Exception):
    pass


def list_findings(
    db: Session, *, severity: Severity | None, status: Status | None,
    asset: str | None, limit: int, offset: int,
) -> tuple[list[Finding], int]:
    q = select(Finding)
    if severity:
        q = q.where(Finding.severity == severity.value)
    if status:
        q = q.where(Finding.status == status.value)
    if asset:
        q = q.where(Finding.asset == asset.strip().lower())  # exact match -> uses the index
    total = db.scalar(select(func.count()).select_from(q.subquery())) or 0
    items = db.scalars(q.order_by(Finding.id).limit(limit).offset(offset)).all()
    return list(items), total


def get_finding(db: Session, finding_id: int) -> Finding | None:
    return db.get(Finding, finding_id)


def change_status(db: Session, finding: Finding, new: Status) -> Finding:
    current = Status(finding.status)
    if new not in TRANSITIONS[current]:
        raise InvalidTransition(f"Cannot move from {current.value} to {new.value}")
    finding.status = new.value
    finding.fixed_at = datetime.now(timezone.utc) if new == Status.fixed else None
    db.commit()
    return finding
