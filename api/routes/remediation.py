import logging

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from api.dependencies import get_db
from api.schemas.autosectwin import RemediationCreate, RemediationResponse
from database.models.remediation import Remediation
from services.revalidation.revalidation_engine import RevalidationEngine

router = APIRouter()
logger = logging.getLogger(__name__)
revalidation_engine = RevalidationEngine()


@router.post("/", response_model=RemediationResponse)
def create_remediation(payload: RemediationCreate, db: Session = Depends(get_db)) -> Remediation:
    """Create a remediation action."""

    remediation = Remediation(**payload.model_dump())
    db.add(remediation)
    db.commit()
    db.refresh(remediation)
    logger.info("Created remediation %s", remediation.id)
    return remediation


@router.post("/{remediation_id}/revalidate", response_model=RemediationResponse)
def revalidate_remediation(remediation_id: int, validation_score: float = 0.0, db: Session = Depends(get_db)) -> Remediation:
    """Run remediation verification from residual validation score."""

    remediation = db.get(Remediation, remediation_id)
    if not remediation:
        raise HTTPException(status_code=404, detail="Remediation not found")
    status, score, evidence = revalidation_engine.verify(validation_score)
    remediation.status = status
    remediation.verification_score = score
    remediation.evidence = evidence
    db.commit()
    db.refresh(remediation)
    return remediation


@router.get("/", response_model=list[RemediationResponse])
def list_remediations(db: Session = Depends(get_db)) -> list[Remediation]:
    """List remediation actions."""

    return db.query(Remediation).order_by(Remediation.id.desc()).all()
