import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from api.dependencies import get_db
from api.schemas.autosectwin import RemediationCreate, RemediationResponse
from database.models.approval import Approval
from database.models.remediation import Remediation
from services.revalidation.revalidation_engine import RevalidationEngine
from services.remediation.patch_executor import PatchExecutor
router = APIRouter()
logger = logging.getLogger(__name__)
revalidation_engine = RevalidationEngine()
class RevalidationRequest(BaseModel):
    validation_score: float = Field(ge=0.0, le=1.0)
    evidence: dict[str, object] | None = None
patch_executor = PatchExecutor()

@router.post("/", response_model=RemediationResponse)
def create_remediation(
    payload: RemediationCreate,
    db: Session = Depends(get_db),
) -> Remediation:
    """Create a remediation only after explicit human approval."""

    if not payload.recommendation_id:
        raise HTTPException(
            status_code=400,
            detail="A recommendation_id is required before remediation.",
        )

    approval = (
        db.query(Approval)
        .filter(
            Approval.vulnerability_id == payload.vulnerability_id,
            Approval.status == "approved",
        )
        .order_by(Approval.decided_at.desc())
        .first()
    )

    if not approval:
        raise HTTPException(
            status_code=403,
            detail=(
                "Remediation requires an approved human approval "
                "record for this vulnerability."
            ),
        )

    approval_context = approval.context or {}
    approved_recommendation_id = approval_context.get("recommendation_id")

    if approved_recommendation_id is not None:
        try:
            approved_recommendation_id = int(approved_recommendation_id)
        except (TypeError, ValueError):
            raise HTTPException(
                status_code=403,
                detail="Approval contains an invalid recommendation reference.",
            )

        if approved_recommendation_id != payload.recommendation_id:
            raise HTTPException(
                status_code=403,
                detail=(
                    "The approved recommendation does not match the "
                    "requested remediation recommendation."
                ),
            )

    remediation = Remediation(
    **payload.model_dump(),
    status="approved",
    evidence={
        "approval_id": approval.id,
        "approved_by": approval.decided_by,
        "approval_context": approval_context,
    },
)

    db.add(remediation)
    db.commit()
    db.refresh(remediation)

    logger.info(
        "Created approved remediation %s using approval %s",
        remediation.id,
        approval.id,
    )

    return remediation

@router.post(
    "/{remediation_id}/execute",
    response_model=RemediationResponse,
)
def execute_remediation(
    remediation_id: int,
    db: Session = Depends(get_db),
) -> Remediation:
    """Execute an explicitly approved remediation."""

    remediation = db.get(Remediation, remediation_id)

    if not remediation:
        raise HTTPException(
            status_code=404,
            detail="Remediation not found",
        )

    if remediation.status != "approved":
        raise HTTPException(
            status_code=409,
            detail=(
                f"Remediation cannot execute from status "
                f"'{remediation.status}'. Expected 'approved'."
            ),
        )

    # ------------------------------------------------------------
    # APPROVED -> QUEUED
    # ------------------------------------------------------------
    remediation.status = "queued"

    evidence = dict(remediation.evidence or {})
    evidence["execution_lifecycle"] = {
        "queued_at": datetime.now(timezone.utc).isoformat(),
    }

    remediation.evidence = evidence

    db.commit()
    db.refresh(remediation)

    # ------------------------------------------------------------
    # QUEUED -> EXECUTING
    # ------------------------------------------------------------
    remediation.status = "executing"

    evidence = dict(remediation.evidence or {})
    evidence["execution_lifecycle"]["executing_at"] = (
        datetime.now(timezone.utc).isoformat()
    )

    remediation.evidence = evidence

    db.commit()
    db.refresh(remediation)

    # ------------------------------------------------------------
    # Execute through the controlled patch handler
    # ------------------------------------------------------------
    approval_context = (
        evidence.get("approval_context")
        or {}
    )

    execution_context = dict(approval_context or {})

    execution_context.setdefault(
        "current_version",
        execution_context.get("detected_version", "5.17.3"),
    )

    execution_context.setdefault(
        "fixed_version",
        execution_context.get("recommended_fixed_version", "5.17.6"),
    )

    result = patch_executor.execute(
        vulnerability_id=remediation.vulnerability_id,
        recommendation_id=remediation.recommendation_id,
        action=remediation.action,
        context=execution_context,
    )

    # ------------------------------------------------------------
    # Persist execution result
    # ------------------------------------------------------------
    remediation.status = result.status

    evidence = dict(remediation.evidence or {})

    evidence["execution"] = result.evidence
    evidence["execution_message"] = result.message
    evidence["execution_lifecycle"]["completed_at"] = (
        datetime.now(timezone.utc).isoformat()
    )

    remediation.evidence = evidence

    if result.status == "executed":
        remediation.applied_at = datetime.now(timezone.utc)

    db.commit()
    db.refresh(remediation)

    logger.info(
        "Remediation %s execution result: %s",
        remediation.id,
        remediation.status,
    )

    return remediation


@router.post("/{remediation_id}/revalidate", response_model=RemediationResponse)
def revalidate_remediation(
    remediation_id: int,
    payload: RevalidationRequest,
    db: Session = Depends(get_db),
) -> Remediation:
    """Verify remediation using post-remediation validation evidence."""

    remediation = db.get(Remediation, remediation_id)

    if not remediation:
        raise HTTPException(
            status_code=404,
            detail="Remediation not found",
        )

    evidence = dict(payload.evidence or {})

    evidence.update(
        {
            "revalidation_type": "post_remediation_validation",
            "validation_score": payload.validation_score,
            "remediation_id": remediation.id,
            "vulnerability_id": remediation.vulnerability_id,
        }
    )

    status, score, verification_evidence = revalidation_engine.verify(
        payload.validation_score,
        evidence=evidence,
    )

    remediation.status = status
    remediation.verification_score = score
    remediation.evidence = {
        **(remediation.evidence or {}),
        "revalidation": verification_evidence,
    }

    from datetime import datetime, timezone

    remediation.verified_at = datetime.now(timezone.utc)

    db.commit()
    db.refresh(remediation)

    logger.info(
        "Remediation %s revalidated: status=%s score=%.3f",
        remediation.id,
        status,
        score,
    )

    return remediation


@router.get(
    "/",
    response_model=list[RemediationResponse],
)
def list_remediations(
    db: Session = Depends(get_db),
) -> list[Remediation]:
    """List remediation actions."""

    return db.query(Remediation).order_by(Remediation.id.desc()).all()