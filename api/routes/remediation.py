import logging

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from sqlalchemy.orm import Session

from api.dependencies import get_db
from api.schemas.autosectwin import (
    RemediationCreate,
    RemediationExecuteRequest,
    RemediationResponse,
)
from core.config import settings
from database.models.remediation import Remediation
from services.remediation import status as remediation_status
from services.remediation.tasks import (
    execute_remediation_job,
    execute_remediation_task,
    revalidate_remediation_job,
    revalidate_remediation_task,
)

router = APIRouter()
logger = logging.getLogger(__name__)

_IN_PROGRESS_STATUSES = {
    remediation_status.QUEUED,
    remediation_status.EXECUTING,
    remediation_status.REVALIDATING,
}

_NOT_YET_EXECUTED_STATUSES = {
    remediation_status.PLANNED,
    remediation_status.APPROVED,
    remediation_status.QUEUED,
    remediation_status.EXECUTING,
}


@router.post("/", response_model=RemediationResponse)
def create_remediation(payload: RemediationCreate, db: Session = Depends(get_db)) -> Remediation:
    """Create a remediation action directly (bypassing the approval
    workflow). Prefer POST /approvals/ + PATCH /approvals/{id}/decision
    for anything that should actually be executed -- PatchExecutor refuses
    to run a remediation with no approved Approval record regardless of
    how the Remediation row was created.
    """

    remediation = Remediation(**payload.model_dump())
    db.add(remediation)
    db.commit()
    db.refresh(remediation)
    logger.info("Created remediation %s", remediation.id)
    return remediation


@router.post("/{remediation_id}/execute", response_model=RemediationResponse, status_code=202)
def execute_remediation(
    remediation_id: int,
    payload: RemediationExecuteRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
) -> Remediation:
    """Execute a remediation: destroy the vulnerable twin, redeploy it at
    fixed_version, and (by default) immediately revalidate. Dispatched as
    a background job (Celery, falling back to inline BackgroundTasks) --
    returns immediately with status=QUEUED; poll GET /remediations/{id}.
    """

    remediation = db.query(Remediation).filter(Remediation.id == remediation_id).first()
    if remediation is None:
        raise HTTPException(status_code=404, detail="Remediation not found")

    if remediation.status in _IN_PROGRESS_STATUSES:
        raise HTTPException(
            status_code=409,
            detail=f"Remediation {remediation_id} is already in progress (status={remediation.status}).",
        )

    remediation.status = remediation_status.QUEUED
    db.commit()
    db.refresh(remediation)

    if settings.TASK_QUEUE_BACKEND == "celery":
        try:
            execute_remediation_task.delay(
                remediation_id, payload.fixed_version, payload.run_revalidation
            )
            return remediation
        except Exception as exc:  # noqa: BLE001 - broker unreachable, etc.
            logger.warning(
                "Celery dispatch failed for remediation %s (%s); falling back to inline.",
                remediation_id,
                exc,
            )

    background_tasks.add_task(
        execute_remediation_job,
        remediation_id,
        payload.fixed_version,
        payload.run_revalidation,
        None,
    )
    return remediation


@router.post("/{remediation_id}/revalidate", response_model=RemediationResponse, status_code=202)
def revalidate_remediation(
    remediation_id: int,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
) -> Remediation:
    """Revalidate a remediation against its current target_twin_id by
    actually re-running the same exploit (RevalidationEngine.run()) and
    comparing it to the original validation.

    This no longer accepts a validation_score from the caller -- the
    validation score is produced by an actual exploit re-execution, not
    supplied by whoever calls this endpoint.
    """

    remediation = db.query(Remediation).filter(Remediation.id == remediation_id).first()
    if remediation is None:
        raise HTTPException(status_code=404, detail="Remediation not found")

    if remediation.status in _NOT_YET_EXECUTED_STATUSES:
        raise HTTPException(
            status_code=409,
            detail=(
                f"Remediation {remediation_id} has not been executed yet "
                f"(status={remediation.status}); nothing to revalidate."
            ),
        )

    remediation.status = remediation_status.REVALIDATING
    db.commit()
    db.refresh(remediation)

    if settings.TASK_QUEUE_BACKEND == "celery":
        try:
            revalidate_remediation_task.delay(remediation_id)
            return remediation
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "Celery dispatch failed for revalidation of remediation %s (%s); "
                "falling back to inline.",
                remediation_id,
                exc,
            )

    background_tasks.add_task(revalidate_remediation_job, remediation_id, None)
    return remediation


@router.get("/", response_model=list[RemediationResponse])
def list_remediations(db: Session = Depends(get_db)) -> list[Remediation]:
    """List remediation actions."""

    return db.query(Remediation).order_by(Remediation.id.desc()).all()


@router.get("/{remediation_id}", response_model=RemediationResponse)
def get_remediation(remediation_id: int, db: Session = Depends(get_db)) -> Remediation:
    """Get a single remediation's current status/evidence."""

    remediation = db.query(Remediation).filter(Remediation.id == remediation_id).first()
    if remediation is None:
        raise HTTPException(status_code=404, detail="Remediation not found")
    return remediation
