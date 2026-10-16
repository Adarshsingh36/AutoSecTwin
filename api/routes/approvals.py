import logging
from pathlib import Path

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from api.dependencies import get_db, pagination
from api.schemas.autosectwin import ApprovalCreate, ApprovalDecision, ApprovalResponse
from core.config import settings
from core.security import Principal, require_role
from database.models.approval import Approval
from database.models.legacy import SpecialistQueue
from database.models.trust import HallucinationLog
from services.approval import workflow
from services.approval.response_parser import interpret_human_response
from services.remediation.tasks import execute_remediation_job, execute_remediation_task
from services.reporting.workflow_report_service import (
    create_approval_decision_report,
    revise_recommendation_review,
)
from services.learning.event_recorder import record_learning_event

router = APIRouter()
logger = logging.getLogger(__name__)


def _to_response(approval: Approval) -> ApprovalResponse:
    response = ApprovalResponse.model_validate(approval)
    response.fixed_version = (approval.context or {}).get("fixed_version")
    response.review_url = f"/approvals/{approval.id}/review"
    response.response_interpretation = (approval.context or {}).get("response_interpretation")
    return response


@router.post("/", response_model=ApprovalResponse)
def create_approval(
    payload: ApprovalCreate,
    db: Session = Depends(get_db),
    _: Principal = Depends(require_role("analyst", "operator", "admin")),
) -> ApprovalResponse:
    """Create a human approval request.

    Builds the full review package (vulnerability, exploit evidence,
    recommendation, target twin, current/fixed version, limitations) and
    attaches it to the approval's context -- a reviewer should never need
    to go hunting for this separately.
    """

    approval = workflow.request_approval(
        db,
        vulnerability_id=payload.vulnerability_id,
        target_twin_id=payload.target_twin_id,
        fixed_version=payload.fixed_version,
        recommendation_id=payload.recommendation_id,
        requested_by=payload.requested_by,
    )
    logger.info("Queued approval %s for %s", approval.id, approval.requested_action)
    return _to_response(approval)


@router.patch("/{approval_id}/decision", response_model=ApprovalResponse)
def decide_approval(
    approval_id: int,
    payload: ApprovalDecision,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    _: Principal = Depends(require_role("approver", "admin")),
) -> ApprovalResponse:
    """Record a human approval decision.

    Rejection stops here -- no Remediation is created. Approval creates
    the Remediation (status=APPROVED) and, if
    settings.REMEDIATION_AUTO_APPLY is on, immediately dispatches its
    execution (and, by default, revalidation) as a background job so this
    request returns promptly rather than blocking on twin
    destroy/provision/exploit re-run.
    """

    pending_approval = db.query(Approval).filter(Approval.id == approval_id).first()
    if pending_approval is None:
        raise HTTPException(status_code=404, detail=f"Approval {approval_id} not found.")

    text_decision = interpret_human_response(payload.human_response)
    decision = payload.status
    if decision is None:
        decision = text_decision

    if text_decision == "revision_requested" or (
        payload.status is None and text_decision == "unclear"
    ):
        approval = pending_approval
        if approval.status != "pending":
            raise HTTPException(status_code=409, detail="This approval has already been decided.")
        revise_recommendation_review(db, approval, payload.human_response or "")
        record_learning_event(
            db,
            event_type="human_review_feedback",
            source="approval_review",
            label=text_decision,
            payload={"approval_id": approval.id, "human_response": payload.human_response},
            notes="Response retained for follow-up; no approval or deployment was performed.",
        )
        return _to_response(approval)

    if decision not in ("approved", "rejected"):
        raise HTTPException(
            status_code=422,
            detail="Respond with a clear yes/approve or no/reject, or request a proposal revision.",
        )

    if text_decision in ("approved", "rejected") and text_decision != decision:
        raise HTTPException(
            status_code=422,
            detail="The selected decision conflicts with the written response. Please submit one clear decision.",
        )

    if decision == "approved" and (pending_approval.context or {}).get("reproposal_required"):
        raise HTTPException(
            status_code=409,
            detail="This proposal was changed by reviewer feedback. Create and review a new approval before deployment.",
        )

    approval = workflow.decide(
        db,
        approval_id=approval_id,
        decision=decision,
        decided_by=payload.decided_by or "reviewer",
        decision_reason=payload.decision_reason or payload.human_response,
    )
    approval.context = {
        **(approval.context or {}),
        "human_response": payload.human_response,
        "response_interpretation": text_decision,
    }
    db.commit()
    db.refresh(approval)
    decision_report = create_approval_decision_report(db, approval)
    approval.context = {
        **(approval.context or {}),
        "decision_report_id": decision_report.id,
    }
    db.commit()
    db.refresh(approval)

    if decision == "approved" and settings.REMEDIATION_AUTO_APPLY and approval.remediation_id:
        fixed_version = (approval.context or {}).get("fixed_version")
        if fixed_version:
            _dispatch_remediation_execution(
                background_tasks, approval.remediation_id, fixed_version
            )
        else:
            logger.warning(
                "Approval %s approved but has no fixed_version in context; "
                "not auto-dispatching remediation %s.",
                approval_id,
                approval.remediation_id,
            )

    return _to_response(approval)


@router.get("/{approval_id}/review", response_class=FileResponse)
def get_approval_review_page(approval_id: int, db: Session = Depends(get_db)) -> FileResponse:
    approval = db.query(Approval).filter(Approval.id == approval_id).first()
    if approval is None:
        raise HTTPException(status_code=404, detail="Approval not found")
    page = Path(__file__).resolve().parents[1] / "static" / "approval_review.html"
    return FileResponse(page, media_type="text/html")


def _dispatch_remediation_execution(
    background_tasks: BackgroundTasks, remediation_id: int, fixed_version: str
) -> None:
    if settings.TASK_QUEUE_BACKEND == "celery":
        try:
            execute_remediation_task.delay(remediation_id, fixed_version, True)
            return
        except Exception as exc:  # noqa: BLE001 - broker unreachable, etc.
            logger.warning(
                "Celery dispatch failed for remediation %s (%s); falling back to inline.",
                remediation_id,
                exc,
            )

    background_tasks.add_task(
        execute_remediation_job, remediation_id, fixed_version, True, None
    )


@router.get("/", response_model=list[ApprovalResponse])
def list_approvals(
    db: Session = Depends(get_db),
    page: tuple[int, int] = Depends(pagination),
) -> list[ApprovalResponse]:
    """List approval requests."""

    approvals = db.query(Approval).order_by(Approval.id.desc()).limit(page[0]).offset(page[1]).all()
    return [_to_response(a) for a in approvals]


@router.get("/legacy")
def list_legacy_review_queue(
    db: Session = Depends(get_db),
    page: tuple[int, int] = Depends(pagination),
) -> list[dict[str, object]]:
    """List pending legacy specialist review items."""

    rows = (
        db.query(SpecialistQueue)
        .filter(SpecialistQueue.queue_type == "legacy", SpecialistQueue.status == "pending")
        .order_by(SpecialistQueue.id.desc())
        .limit(page[0])
        .offset(page[1])
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
    page: tuple[int, int] = Depends(pagination),
) -> list[dict[str, object]]:
    """List pending hallucination review items."""

    rows = (
        db.query(HallucinationLog)
        .filter(HallucinationLog.review_status == "pending")
        .order_by(HallucinationLog.id.desc())
        .limit(page[0])
        .offset(page[1])
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


@router.get("/{approval_id}", response_model=ApprovalResponse)
def get_approval(approval_id: int, db: Session = Depends(get_db)) -> ApprovalResponse:
    approval = db.query(Approval).filter(Approval.id == approval_id).first()
    if approval is None:
        raise HTTPException(status_code=404, detail="Approval not found")
    return _to_response(approval)
