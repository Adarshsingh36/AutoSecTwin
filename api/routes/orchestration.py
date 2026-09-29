import logging
import uuid

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from api.dependencies import get_db
from core.config import settings
from database.models.orchestration_job import OrchestrationJob
from database.models.vulnerability import Vulnerability
from database.session import SessionLocal
from services.orchestration.closed_loop_orchestrator import ClosedLoopOrchestrator

router = APIRouter()
logger = logging.getLogger(__name__)


class OrchestrationRunRequest(BaseModel):
    vulnerability_id: int
    auto_apply_remediation: bool | None = None
    destroy_twin_after: bool | None = None


class OrchestrationJobResponse(BaseModel):
    job_id: str
    vulnerability_id: int
    status: str
    stage: str
    progress: int
    message: str | None = None
    mock_mode: bool
    queue_backend: str
    result: dict | None = None
    error: str | None = None

    model_config = {"from_attributes": False}

    @classmethod
    def from_model(cls, job: OrchestrationJob) -> "OrchestrationJobResponse":
        return cls(
            job_id=job.job_id,
            vulnerability_id=job.vulnerability_id,
            status=job.status,
            stage=job.stage,
            progress=job.progress,
            message=job.message,
            mock_mode=job.mock_mode == "true",
            queue_backend=job.queue_backend,
            result=job.result_json,
            error=job.error,
        )


def _run_job_in_background(job_id: str) -> None:
    """Entry point for FastAPI BackgroundTasks.

    Opens its own database session because the request-scoped session from
    ``get_db`` is closed as soon as the HTTP response is sent -- the whole
    point of running this in the background is that it keeps working after
    the response has already gone out.
    """

    import asyncio

    db = SessionLocal()
    try:
        job = db.query(OrchestrationJob).filter(OrchestrationJob.job_id == job_id).first()
        if job is None:
            logger.error("Orchestration job %s vanished before it could run.", job_id)
            return

        orchestrator = ClosedLoopOrchestrator()
        try:
            asyncio.run(orchestrator.run(db, job))
        except Exception:
            # ClosedLoopOrchestrator already persists failure state onto the
            # job row before re-raising; nothing further to do here besides
            # making sure it doesn't propagate into BackgroundTasks/uvicorn.
            logger.exception("Orchestration job %s ended with an error.", job_id)
    finally:
        db.close()


def _dispatch(job: OrchestrationJob, background_tasks: BackgroundTasks, db: Session) -> str:
    """Dispatch a queued job to a worker and return which backend ran it.

    Prefers Celery (a real, separate worker process/machine, per the
    "HTTP requests must not block" requirement) but falls back to
    in-process ``BackgroundTasks`` if Celery dispatch itself fails --
    typically because no broker (Redis) is reachable in a local/demo
    environment. The fallback is logged loudly since it's a degraded mode,
    not silently swallowed.
    """

    if settings.TASK_QUEUE_BACKEND == "celery":
        try:
            from services.tasks.orchestration_tasks import run_closed_loop_job

            run_closed_loop_job.delay(job.job_id)
            return "celery"
        except Exception as exc:  # noqa: BLE001 - broker unreachable, misconfigured, etc.
            logger.warning(
                "Celery dispatch failed for job %s (%s); falling back to inline BackgroundTasks. "
                "Is a Celery worker + broker (CELERY_BROKER_URL=%s) running?",
                job.job_id,
                exc,
                settings.CELERY_BROKER_URL,
            )

    background_tasks.add_task(_run_job_in_background, job.job_id)
    return "inline"


@router.post("/run", response_model=OrchestrationJobResponse, status_code=202)
def run_orchestration(
    payload: OrchestrationRunRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
) -> OrchestrationJobResponse:
    """Submit a vulnerability for the full closed-loop workflow.

    Returns immediately with a job id; the workflow (twin provisioning,
    Metasploit validation, remediation, revalidation, reporting) runs on a
    Celery worker (or, as a fallback, an in-process background task) so
    this call never blocks on long-running infrastructure.
    """

    vulnerability = db.get(Vulnerability, payload.vulnerability_id)
    if vulnerability is None:
        raise HTTPException(status_code=404, detail=f"Vulnerability {payload.vulnerability_id} not found.")

    job = OrchestrationJob(
        job_id=uuid.uuid4().hex,
        vulnerability_id=vulnerability.id,
        status="queued",
        stage="assessment",
        progress=0,
        message="Job queued.",
    )
    db.add(job)
    db.commit()
    db.refresh(job)

    queue_backend = _dispatch(job, background_tasks, db)
    job.queue_backend = queue_backend
    db.commit()
    db.refresh(job)

    logger.info(
        "Queued orchestration job %s for vulnerability %s via %s",
        job.job_id,
        vulnerability.id,
        queue_backend,
    )

    return OrchestrationJobResponse.from_model(job)


@router.get("/", response_model=list[OrchestrationJobResponse])
def list_orchestration_jobs(db: Session = Depends(get_db)) -> list[OrchestrationJobResponse]:
    """List recent closed-loop orchestration jobs."""

    jobs = db.query(OrchestrationJob).order_by(OrchestrationJob.id.desc()).all()
    return [OrchestrationJobResponse.from_model(job) for job in jobs]


@router.get("/{job_id}", response_model=OrchestrationJobResponse)
def get_orchestration_job(job_id: str, db: Session = Depends(get_db)) -> OrchestrationJobResponse:
    """Poll the status of a closed-loop orchestration job."""

    job = db.query(OrchestrationJob).filter(OrchestrationJob.job_id == job_id).first()
    if job is None:
        raise HTTPException(status_code=404, detail="Orchestration job not found")
    return OrchestrationJobResponse.from_model(job)
