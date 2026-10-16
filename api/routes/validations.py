import json
import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from api.dependencies import get_db, pagination
from api.schemas.autosectwin import ValidationCreate, ValidationResponse
from core.security import Principal, require_role
from database.models.validation import Validation
from database.models.exploit import Exploit
from database.models.twin import Twin
from database.models.vulnerability import Vulnerability
from services.approval.workflow import request_recommendation_review
from services.recommendation.recommendation_engine import RecommendationEngine
from services.reporting.workflow_report_service import create_validation_report
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

    vulnerability = db.get(Vulnerability, payload.vulnerability_id)
    exploit = db.get(Exploit, payload.exploit_id) if payload.exploit_id else None
    twin = db.get(Twin, payload.twin_id) if payload.twin_id else None
    recommendation = None
    submitted_findings = (payload.evidence or {}).get("findings")
    if validation.status == "validated" or submitted_findings:
        recommendation = RecommendationEngine(db).generate(
            vulnerability_id=payload.vulnerability_id,
            recommendation_type="patch",
            context={
                "validation_id": validation.id,
                "validation_status": validation.status,
                "evidence_source": "user_submitted_evidence",
            },
        )

    report = create_validation_report(
        db,
        vulnerability=vulnerability,
        validation=validation,
        exploit=exploit,
        twin=twin,
        recommendation=recommendation,
        evidence_source="user_submitted_evidence",
    )
    approval = None
    if recommendation is not None:
        report_body = json.loads(report.content)
        report_findings = report_body.get("findings", {})
        review_package = {
            "plain_language": report_findings.get("plain_language", {}),
            "validation_status": validation.status,
            "findings": submitted_findings or [],
            "recommendation": {
                "id": recommendation.id,
                "title": recommendation.title,
                "content": recommendation.content,
            },
            "report_id": report.id,
            "limitations": [
                "This is a recommendation review, not approval to deploy a change.",
                "An inconclusive validation does not imply a successful exploit or credential compromise.",
            ],
        }
        approval = request_recommendation_review(
            db,
            vulnerability_id=payload.vulnerability_id,
            recommendation_id=recommendation.id,
            report_id=report.id,
            review_package=review_package,
        )
    validation.report_id = report.id
    validation.recommendation_id = recommendation.id if recommendation else None
    validation.approval_id = approval.id if approval else None
    validation.review_url = f"/approvals/{approval.id}/review" if approval else None
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
