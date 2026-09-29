import logging
from datetime import datetime, timezone
from typing import Any
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from api.dependencies import get_db
from api.schemas.autosectwin import (
    ApprovalCreate,
    ApprovalDecision,
    ApprovalResponse,
    HumanReviewResponse,
)
from database.models.approval import Approval
from database.models.legacy import SpecialistQueue
from database.models.recommendation import Recommendation
from database.models.trust import HallucinationLog
from database.models.vulnerability import Vulnerability

router = APIRouter()
logger = logging.getLogger(__name__)


@router.get(
    "/review/{vulnerability_id}",
    response_model=HumanReviewResponse,
)
def get_human_review(
    vulnerability_id: int,
    db: Session = Depends(get_db),
) -> dict:
    """Build the complete human-review package before remediation approval."""

    vulnerability = db.get(Vulnerability, vulnerability_id)

    if not vulnerability:
        raise HTTPException(
            status_code=404,
            detail="Vulnerability not found",
        )

    recommendation = (
        db.query(Recommendation)
        .filter(
            Recommendation.vulnerability_id == vulnerability_id,
        )
        .order_by(Recommendation.id.desc())
        .first()
    )

    if not recommendation:
        raise HTTPException(
            status_code=404,
            detail=(
                "No remediation recommendation exists for this vulnerability. "
                "Generate a recommendation before requesting human approval."
            ),
        )

    metadata = recommendation.metadata_json or {}
    explanation = metadata.get("explanation") or {}

    return {
        "vulnerability_id": vulnerability.id,
        "cve_id": vulnerability.cve_id,
        "title": getattr(vulnerability, "title", None),
        "severity": getattr(vulnerability, "severity", None),
        "cvss_score": getattr(vulnerability, "cvss_score", None),

        "vulnerability_explanation": {
            "why_vulnerable": explanation.get("why_vulnerable"),
            "how_it_can_be_exploited": explanation.get(
                "how_it_can_be_exploited"
            ),
            "validation_evidence": explanation.get(
                "validation_evidence"
            ),
            "limitations": explanation.get("limitations", []),
        },

        "recommendation_id": recommendation.id,
        "recommendation_type": recommendation.recommendation_type,
        "recommendation_title": recommendation.title,
        "recommendation_content": recommendation.content,
        "recommendation_provider": recommendation.provider,

        "remediation_explanation": {
            "remediation_category": explanation.get(
                "remediation_category"
            ),
            "recommended_fix": explanation.get(
                "recommended_fix"
            ),
            "why_fix_works": explanation.get(
                "why_fix_works"
            ),
            "code_change_required": explanation.get(
                "code_change_required",
                False,
            ),
            "proposed_code_change": explanation.get(
                "proposed_code_change"
            ),
            "human_approval_required": explanation.get(
                "human_approval_required",
                True,
            ),
            "approval_reason": explanation.get(
                "approval_reason"
            ),
            "limitations": explanation.get("limitations", []),
        },

        "human_approval_required": explanation.get(
            "human_approval_required",
            True,
        ),

        "approval_status": "ready_for_review",
    }


@router.post("/", response_model=ApprovalResponse)
def create_approval(
    payload: ApprovalCreate,
    db: Session = Depends(get_db),
) -> Approval:
    """Create a human approval request."""

    approval = Approval(**payload.model_dump())
    db.add(approval)
    db.commit()
    db.refresh(approval)

    logger.info(
        "Queued approval %s for %s",
        approval.id,
        approval.requested_action,
    )

    return approval


@router.patch("/{approval_id}/decision", response_model=ApprovalResponse)
def decide_approval(
    approval_id: int,
    payload: ApprovalDecision,
    db: Session = Depends(get_db),
) -> Approval:
    approval = db.get(Approval, approval_id)

    if not approval:
        raise HTTPException(
            status_code=404,
            detail="Approval not found",
        )

    approval.status = payload.status
    approval.decided_by = payload.decided_by
    approval.decision_reason = payload.decision_reason

    # Preserve the existing approval context and attach reviewer input.
    context = dict(approval.context or {})

    if payload.reviewer_input is not None:
        context["reviewer_input"] = payload.reviewer_input

    approval.context = context
    approval.decided_at = datetime.now(timezone.utc)

    db.commit()
    db.refresh(approval)

    logger.info(
        "Approval %s decided as %s by %s",
        approval.id,
        approval.status,
        approval.decided_by,
    )

    return approval
@router.get(
    "/",
    response_model=list[ApprovalResponse],
)
def list_approvals(
    db: Session = Depends(get_db),
) -> list[Approval]:
    """List approval requests."""

    return (
        db.query(Approval)
        .order_by(Approval.id.desc())
        .all()
    )


@router.get("/legacy")
def list_legacy_review_queue(
    db: Session = Depends(get_db),
) -> list[dict[str, object]]:
    """List pending legacy specialist review items."""

    rows = (
        db.query(SpecialistQueue)
        .filter(
            SpecialistQueue.queue_type == "legacy",
            SpecialistQueue.status == "pending",
        )
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
def list_hallucination_review_queue(
    db: Session = Depends(get_db),
) -> list[dict[str, object]]:
    """List pending hallucination review items."""

    rows = (
        db.query(HallucinationLog)
        .filter(
            HallucinationLog.review_status == "pending"
        )
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