import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from api.dependencies import get_db
from api.schemas.autosectwin import ApprovalCreate, ApprovalDecision, ApprovalResponse
from database.models.approval import Approval
from database.models.legacy import SpecialistQueue
from database.models.trust import HallucinationLog

router = APIRouter()
logger = logging.getLogger(__name__)


@router.post("/", response_model=ApprovalResponse)
def create_approval(payload: ApprovalCreate, db: Session = Depends(get_db)) -> Approval:
    """Create a human approval request."""

    approval = Approval(**payload.model_dump())
    db.add(approval)
    db.commit()
    db.refresh(approval)
    logger.info("Queued approval %s for %s", approval.id, approval.requested_action)
    return approval


@router.patch("/{approval_id}/decision", response_model=ApprovalResponse)
def decide_approval(approval_id: int, payload: ApprovalDecision, db: Session = Depends(get_db)) -> Approval:
    """Record a human approval decision."""

    approval = db.get(Approval, approval_id)
    if not approval:
        raise HTTPException(status_code=404, detail="Approval not found")
    approval.status = payload.status
    approval.decided_by = payload.decided_by
    approval.decision_reason = payload.decision_reason
    approval.decided_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(approval)
    return approval


@router.get("/", response_model=list[ApprovalResponse])
def list_approvals(db: Session = Depends(get_db)) -> list[Approval]:
    """List approval requests."""

    return db.query(Approval).order_by(Approval.id.desc()).all()


@router.get("/legacy")
def list_legacy_review_queue(db: Session = Depends(get_db)) -> list[dict[str, object]]:
    """List pending legacy specialist review items."""

    rows = (
        db.query(SpecialistQueue)
        .filter(SpecialistQueue.queue_type == "legacy", SpecialistQueue.status == "pending")
        .order_by(SpecialistQueue.id.desc())
        .all()
    )
    return [
        {
            "id": row.id,
            "legacy_profile_id": row.legacy_profile_id,
            "status": row.status,
            "reason": row.reason,
            "payload": row.payload,
            "created_at": row.created_at,
        }
        for row in rows
    ]


@router.get("/hallucinations")
def list_hallucination_review_queue(db: Session = Depends(get_db)) -> list[dict[str, object]]:
    """List pending hallucination review items."""

    rows = (
        db.query(HallucinationLog)
        .filter(HallucinationLog.review_status == "pending")
        .order_by(HallucinationLog.id.desc())
        .all()
    )
    return [
        {
            "id": row.id,
            "vulnerability_id": row.vulnerability_id,
            "severity": row.severity,
            "reason": row.reason,
            "prediction_score": row.prediction_score,
            "validation_score": row.validation_score,
            "created_at": row.created_at,
        }
        for row in rows
    ]
