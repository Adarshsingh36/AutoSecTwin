"""
Celery task for dispatching a closed-loop orchestration run.

This module is the single source of truth for "what happens when a job
runs" -- both the Celery dispatch path and the inline BackgroundTasks
fallback path (see api/routes/orchestration.py) call
`execute_orchestration_job`, so behavior never diverges between the two
backends.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from core.celery_app import celery_app
from database.models.orchestration_job import OrchestrationJob
from database.session import SessionLocal
from services.orchestration.closed_loop_orchestrator import ClosedLoopOrchestrator

logger = logging.getLogger(__name__)


def execute_orchestration_job(
    job_id: int,
    vulnerability_id: int,
    ttl_seconds: int | None,
    dispatch_backend: str,
    db: Session | None = None,
) -> None:
    """Run the closed loop for `job_id` and persist the outcome onto its
    OrchestrationJob row. Never raises -- all failure is captured onto the
    job row itself, since this runs in the background with no HTTP
    response to return an error through.
    """

    owns_session = db is None
    session = db or SessionLocal()

    try:
        job = session.query(OrchestrationJob).filter(OrchestrationJob.id == job_id).first()

        if job is None:
            logger.error("OrchestrationJob %s not found; cannot run.", job_id)
            return

        job.status = "running"
        job.dispatch_backend = dispatch_backend
        job.started_at = datetime.now(timezone.utc)
        session.commit()

        try:
            orchestrator = ClosedLoopOrchestrator(session)
            summary = asyncio.run(
                orchestrator.run(vulnerability_id, ttl_seconds=ttl_seconds)
            )

            job.status = "completed"
            job.result_summary = summary
            job.error_message = None

        except Exception as exc:  # noqa: BLE001 - deliberately broad: this is a background job boundary
            logger.exception("Orchestration job %s failed.", job_id)
            session.rollback()
            job = session.query(OrchestrationJob).filter(OrchestrationJob.id == job_id).first()
            job.status = "failed"
            job.error_message = str(exc)

        job.completed_at = datetime.now(timezone.utc)
        session.commit()

    finally:
        if owns_session:
            session.close()


@celery_app.task(name="orchestration.run_closed_loop", bind=True)
def run_closed_loop_task(
    self,
    job_id: int,
    vulnerability_id: int,
    ttl_seconds: int | None = None,
) -> None:
    """Celery entrypoint. Opens its own DB session -- Celery workers run in
    a separate process/thread from the FastAPI request that dispatched
    this, so the request-scoped session cannot be reused here.
    """

    execute_orchestration_job(
        job_id=job_id,
        vulnerability_id=vulnerability_id,
        ttl_seconds=ttl_seconds,
        dispatch_backend="celery",
        db=None,
    )
