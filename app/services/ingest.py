"""Business logic: turn scanner output into deduplicated findings."""
import hashlib
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.finding import Finding
from app.schemas.enums import Status
from app.schemas.finding import IngestRequest, IngestResult

_CHUNK = 500  # keep under SQLite's bound-parameter limit


def make_fingerprint(scanner: str, asset: str, plugin_id: str) -> str:
    key = "|".join(p.strip().lower() for p in (scanner, asset, plugin_id))
    return hashlib.sha256(key.encode()).hexdigest()


def ingest_findings(db: Session, payload: IngestRequest) -> IngestResult:
    now = datetime.now(timezone.utc)
    scanner = payload.scanner.strip().lower()

    # 1) de-duplicate inside the payload itself (last one wins)
    unique = {make_fingerprint(scanner, f.asset, f.plugin_id): f for f in payload.findings}

    # 2) load existing rows in chunks (one query per 500, not one per finding)
    existing: dict[str, Finding] = {}
    fps = list(unique)
    for i in range(0, len(fps), _CHUNK):
        rows = db.scalars(select(Finding).where(Finding.fingerprint.in_(fps[i : i + _CHUNK])))
        existing.update({r.fingerprint: r for r in rows})

    created = updated = reopened = 0
    for fp, item in unique.items():
        row = existing.get(fp)
        if row is None:
            db.add(
                Finding(
                    fingerprint=fp, scanner=scanner, asset=item.asset.lower(), plugin_id=item.plugin_id,
                    title=item.title, severity=item.severity.value, status=Status.open.value,
                    cve=item.cve, description=item.description, first_seen=now, last_seen=now,
                )
            )
            created += 1
        else:
            row.last_seen = now
            row.severity = item.severity.value
            row.title = item.title
            if row.status == Status.fixed.value:  # scanner saw it again -> regression
                row.status = Status.open.value
                row.fixed_at = None
                reopened += 1
            updated += 1

    db.commit()
    return IngestResult(received=len(unique), created=created, updated=updated, reopened=reopened)
