import asyncio
import logging

from database.models.orchestration_job import OrchestrationJob
from database.session import SessionLocal
from services.orchestration.closed_loop_orchestrator import ClosedLoopOrchestrator
from services.tasks.celery_app import celery_app

logger = logging.getLogger(__name__)


@celery_app.task(name="autosectwin.run_closed_loop_job", bind=True, max_retries=0)
def run_closed_loop_job(self, job_id: str) -> dict:
    """Celery task entry point for a closed-loop AutoSecTwin run.

    Runs on a Celery worker process, fully decoupled from the FastAPI
    request/response cycle, so ``POST /orchestration/run`` never blocks on
    twin provisioning, Metasploit execution, remediation, or revalidation.

    Opens its own database session -- the request-scoped session is long
    gone by the time a worker (possibly on a different machine) picks this
    up. ``ClosedLoopOrchestrator.run`` already persists every stage
    transition and the final failure/success state onto the
    ``OrchestrationJob`` row itself, so this task's return value is just a
    convenience summary for Celery's own result backend/inspection tools.
    """

    db = SessionLocal()
    try:
        job = db.query(OrchestrationJob).filter(OrchestrationJob.job_id == job_id).first()
        if job is None:
            logger.error("Orchestration job %s vanished before the worker could run it.", job_id)
            return {"job_id": job_id, "status": "missing"}

        orchestrator = ClosedLoopOrchestrator()
        try:
            result = asyncio.run(orchestrator.run(db, job))
            return {"job_id": job_id, "status": "completed", "final_status": result.final_status}
        except Exception as exc:  # noqa: BLE001 - job row already carries the failure detail
            logger.exception("Orchestration job %s ended with an error on the worker.", job_id)
            return {"job_id": job_id, "status": "failed", "error": str(exc)}
    finally:
        db.close()
