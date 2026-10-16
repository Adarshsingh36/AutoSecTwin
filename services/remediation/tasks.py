"""
Celery task for dispatching the remediation pipeline (execute + optional
revalidation). Same shape as services/orchestration/tasks.py: one function
(`execute_remediation_job`) is the single source of truth for "what
happens when this runs", called by both the Celery task and the inline
BackgroundTasks fallback in api/routes/remediation.py.
"""

from __future__ import annotations

import asyncio
import logging

from sqlalchemy.orm import Session

from core.celery_app import celery_app
from database.models.remediation import Remediation
from database.session import SessionLocal
from services.reporting.closed_loop_report_service import persist_closed_loop_report
from services.remediation.pipeline import run_remediation_pipeline, run_revalidation_only

logger = logging.getLogger(__name__)


def _persist_final_report(session: Session, remediation_id: int) -> None:
    report = persist_closed_loop_report(session, remediation_id)
    remediation = session.get(Remediation, remediation_id)
    if remediation is None:
        return

    remediation.evidence = {
        **(remediation.evidence or {}),
        "closed_loop_report_id": report.id,
    }
    session.commit()


def execute_remediation_job(
    remediation_id: int,
    fixed_version: str,
    run_revalidation: bool,
    db: Session | None = None,
) -> None:
    """Run the full execute(+revalidate) pipeline. Never raises -- failure
    is recorded onto the Remediation row itself (PatchExecutor/pipeline
    already do this); this wrapper only needs to make sure a session
    exists and is cleaned up, and that nothing escapes to crash a
    background worker/task silently.
    """

    owns_session = db is None
    session = db or SessionLocal()

    try:
        asyncio.run(
            run_remediation_pipeline(
                session, remediation_id, fixed_version, run_revalidation=run_revalidation
            )
        )
    except Exception:  # noqa: BLE001 - background job boundary
        session.rollback()
        logger.exception("Remediation pipeline job failed for remediation %s", remediation_id)
    try:
        _persist_final_report(session, remediation_id)
    except Exception:  # noqa: BLE001 - report generation must not mask job outcome
        session.rollback()
        logger.exception("Final report generation failed for remediation %s", remediation_id)
    finally:
        if owns_session:
            session.close()


def revalidate_remediation_job(
    remediation_id: int,
    db: Session | None = None,
) -> None:
    """Run revalidation only, against whatever target_twin_id the
    remediation currently points to -- does not (re)execute remediation.
    """

    owns_session = db is None
    session = db or SessionLocal()

    try:
        asyncio.run(run_revalidation_only(session, remediation_id))
    except Exception:  # noqa: BLE001 - background job boundary
        session.rollback()
        logger.exception("Revalidation job failed for remediation %s", remediation_id)
    try:
        _persist_final_report(session, remediation_id)
    except Exception:  # noqa: BLE001 - report generation must not mask job outcome
        session.rollback()
        logger.exception("Final report generation failed for remediation %s", remediation_id)
    finally:
        if owns_session:
            session.close()


@celery_app.task(name="remediation.execute", bind=True)
def execute_remediation_task(
    self, remediation_id: int, fixed_version: str, run_revalidation: bool = True
) -> None:
    execute_remediation_job(remediation_id, fixed_version, run_revalidation, db=None)


@celery_app.task(name="remediation.revalidate", bind=True)
def revalidate_remediation_task(self, remediation_id: int) -> None:
    revalidate_remediation_job(remediation_id, db=None)
