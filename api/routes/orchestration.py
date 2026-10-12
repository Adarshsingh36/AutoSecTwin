import logging

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from sqlalchemy.orm import Session

from api.dependencies import get_db
from api.schemas.autosectwin import OrchestrationJobResponse, OrchestrationRunRequest
from core.config import settings
from database.models.orchestration_job import OrchestrationJob
from database.models.vulnerability import Vulnerability
from services.orchestration.tasks import execute_orchestration_job, run_closed_loop_task

logger = logging.getLogger(__name__)

router = APIRouter()


@router.post("/run", response_model=OrchestrationJobResponse, status_code=202)
def run_orchestration(
    payload: OrchestrationRunRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
) -> OrchestrationJob:
    """
    Dispatch a closed-loop orchestration run for a vulnerability.

    Runs Twin provisioning -> exploit validation -> recommendation
    generation, then stops at the human-approval gate (see
    ClosedLoopOrchestrator's module docstring for why). Returns
    immediately with a job id in "queued" status; poll
    GET /orchestration/jobs/{id} for progress and results.
    """

    vulnerability = (
        db.query(Vulnerability)
        .filter(Vulnerability.id == payload.vulnerability_id)
        .first()
    )

    if vulnerability is None:
        raise HTTPException(
            status_code=404,
            detail=f"Vulnerability {payload.vulnerability_id} not found.",
        )

    job = OrchestrationJob(
        vulnerability_id=payload.vulnerability_id,
        job_type="closed_loop_validation",
        status="queued",
    )

    db.add(job)
    db.commit()
    db.refresh(job)

    dispatch_backend = "inline"

    if settings.TASK_QUEUE_BACKEND == "celery":
        try:
            async_result = run_closed_loop_task.delay(
                job.id, payload.vulnerability_id, payload.ttl_seconds
            )
            job.celery_task_id = async_result.id
            job.dispatch_backend = "celery"
            db.commit()
            db.refresh(job)
            return job

        except Exception as exc:  # noqa: BLE001 - broker unreachable, etc.
            logger.warning(
                "Celery dispatch failed for orchestration job %s (%s); "
                "falling back to inline BackgroundTasks.",
                job.id,
                exc,
            )
            dispatch_backend = "inline"

    background_tasks.add_task(
        execute_orchestration_job,
        job_id=job.id,
        vulnerability_id=payload.vulnerability_id,
        ttl_seconds=payload.ttl_seconds,
        dispatch_backend=dispatch_backend,
        db=None,
    )

    job.dispatch_backend = dispatch_backend
    db.commit()
    db.refresh(job)

    return job


@router.get("/jobs/{job_id}", response_model=OrchestrationJobResponse)
def get_orchestration_job(job_id: int, db: Session = Depends(get_db)) -> OrchestrationJob:
    """Fetch the current status/result of one orchestration job."""

    job = db.query(OrchestrationJob).filter(OrchestrationJob.id == job_id).first()

    if job is None:
        raise HTTPException(status_code=404, detail=f"Orchestration job {job_id} not found.")

    return job


@router.get("/jobs", response_model=list[OrchestrationJobResponse])
def list_orchestration_jobs(
    vulnerability_id: int | None = None,
    limit: int = 50,
    db: Session = Depends(get_db),
) -> list[OrchestrationJob]:
    """List orchestration jobs, most recent first, optionally filtered by vulnerability."""

    query = db.query(OrchestrationJob)

    if vulnerability_id is not None:
        query = query.filter(OrchestrationJob.vulnerability_id == vulnerability_id)

    return (
        query.order_by(OrchestrationJob.created_at.desc())
        .limit(limit)
        .all()
    )
