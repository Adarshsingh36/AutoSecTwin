import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from api.dependencies import get_db, pagination
from api.schemas.autosectwin import ValidationCreate, ValidationResponse
from core.security import Principal, require_role
from database.models.validation import Validation
from services.validation.validation_engine import ValidationEngine

router = APIRouter()
logger = logging.getLogger(__name__)
engine = ValidationEngine()


@router.post("/", response_model=ValidationResponse)
def create_validation(
    payload: ValidationCreate,
    db: Session = Depends(get_db),
    _: Principal = Depends(require_role("analyst", "operator", "admin")),
) -> Validation:
    """Analyze exploit evidence and persist validation result."""

    status, score, analysis = engine.analyze(payload.evidence)
    validation = Validation(
        **payload.model_dump(),
        status=status,
        validation_score=score,
        analysis=analysis,
        started_at=datetime.now(timezone.utc),
        completed_at=datetime.now(timezone.utc),
    )
    db.add(validation)
    db.commit()
    db.refresh(validation)
    logger.info("Created validation %s with score %.3f", validation.id, validation.validation_score)
    return validation


@router.get("/", response_model=list[ValidationResponse])
def list_validations(
    db: Session = Depends(get_db),
    page: tuple[int, int] = Depends(pagination),
) -> list[Validation]:
    """List validation results."""

    return db.query(Validation).order_by(Validation.id.desc()).limit(page[0]).offset(page[1]).all()


@router.get("/{validation_id}", response_model=ValidationResponse)
def get_validation(validation_id: int, db: Session = Depends(get_db)) -> Validation:
    """Fetch a validation result."""

    validation = db.get(Validation, validation_id)
    if not validation:
        raise HTTPException(status_code=404, detail="Validation not found")
    return validation
