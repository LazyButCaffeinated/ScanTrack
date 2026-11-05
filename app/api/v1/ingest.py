from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.deps import ANALYST_UP, get_db
from app.schemas.finding import IngestRequest, IngestResult
from app.services.ingest import ingest_findings

router = APIRouter(prefix="/ingest", tags=["ingest"], dependencies=[ANALYST_UP])


@router.post("", response_model=IngestResult)
def ingest(body: IngestRequest, db: Session = Depends(get_db)):
    return ingest_findings(db, body)
