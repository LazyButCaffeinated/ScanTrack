from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.api.deps import ANALYST_UP, ANY_USER, get_db
from app.schemas.enums import Severity, Status
from app.schemas.finding import FindingOut, FindingPage, StatusUpdate
from app.services import findings as svc

router = APIRouter(prefix="/findings", tags=["findings"], dependencies=[ANY_USER])


@router.get("", response_model=FindingPage)
def list_findings(
    severity: Severity | None = None,
    status_: Status | None = Query(None, alias="status"),
    asset: str | None = Query(None, max_length=255),
    limit: int = Query(50, ge=1, le=200),  # hard cap protects the DB
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
):
    items, total = svc.list_findings(db, severity=severity, status=status_, asset=asset, limit=limit, offset=offset)
    return FindingPage(items=items, total=total, limit=limit, offset=offset)


@router.get("/{finding_id}", response_model=FindingOut)
def get_finding(finding_id: int, db: Session = Depends(get_db)):
    finding = svc.get_finding(db, finding_id)
    if finding is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Finding not found")
    return finding


@router.patch("/{finding_id}/status", response_model=FindingOut, dependencies=[ANALYST_UP])
def update_status(finding_id: int, body: StatusUpdate, db: Session = Depends(get_db)):
    finding = svc.get_finding(db, finding_id)
    if finding is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Finding not found")
    try:
        return svc.change_status(db, finding, body.status)
    except svc.InvalidTransition as e:
        raise HTTPException(status.HTTP_409_CONFLICT, str(e))
