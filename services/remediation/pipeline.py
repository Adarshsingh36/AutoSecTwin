"""
Connects PatchExecutor (Phase 4) and RevalidationEngine (already real,
just previously unused) into the full lifecycle:

    APPROVED -> QUEUED -> EXECUTING -> EXECUTED -> REVALIDATING -> VERIFIED
                                            |
                                            v
                                  FAILED / MANUAL_ACTION_REQUIRED

run_remediation_pipeline() is the single entrypoint both the Celery task
and the inline BackgroundTasks fallback call (see services/remediation/tasks.py
and api/routes/remediation.py) -- so dispatch backend never changes
behavior, only timing.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy.orm import Session

from database.models.exploit import Exploit
from database.models.remediation import Remediation
from database.models.twin import Twin
from database.models.validation import Validation
from services.remediation import status as remediation_status
from services.remediation.comparison import build_before_after_comparison
from services.remediation.patch_executor import PatchExecutor
from services.revalidation.revalidation_engine import RevalidationEngine

logger = logging.getLogger(__name__)


async def run_remediation_pipeline(
    db: Session,
    remediation_id: int,
    fixed_version: str,
    run_revalidation: bool = True,
) -> Remediation:
    """Execute a remediation, then (by default) immediately revalidate it
    against the new twin. If execution doesn't reach EXECUTED (precondition
    failure -> MANUAL_ACTION_REQUIRED, or an execution-time failure ->
    FAILED), revalidation is never attempted -- there would be nothing
    meaningful to revalidate against.
    """

    executor = PatchExecutor(db)
    remediation = await executor.execute(remediation_id, fixed_version)

    if remediation.status != remediation_status.EXECUTED:
        logger.info(
            "Remediation %s did not reach EXECUTED (status=%s); skipping revalidation.",
            remediation_id,
            remediation.status,
        )
        return remediation

    if not run_revalidation:
        return remediation

    return await run_revalidation_only(db, remediation.id)


async def run_revalidation_only(db: Session, remediation_id: int) -> Remediation:
    """Revalidate a remediation against whatever twin its target_twin_id
    currently points to -- normally the new (fixed) twin after a
    successful execute(), but callable standalone too (e.g. re-testing
    after a manual fix, or retrying a revalidation that was previously
    inconclusive).
    """

    remediation = (
        db.query(Remediation).filter(Remediation.id == remediation_id).first()
    )
    if remediation is None:
        raise ValueError(f"Remediation {remediation_id} not found.")

    if remediation.target_twin_id is None:
        return _require_manual_action(
            db, remediation, "Remediation has no target_twin_id to revalidate against."
        )

    twin = db.query(Twin).filter(Twin.id == remediation.target_twin_id).first()
    if twin is None:
        return _require_manual_action(
            db, remediation, f"Target twin {remediation.target_twin_id} not found."
        )

    ready_health_values = {"healthy", "ready", "running"}
    status_value = (twin.status or "").lower()
    health_value = (twin.health or "").lower()
    ready_for_revalidation = (
        status_value in {"ready", "running", "healthy"}
        or health_value in ready_health_values
    )
    stale_health = bool(health_value) and health_value not in ready_health_values and status_value not in {"ready", "running", "healthy"}
    if not ready_for_revalidation or stale_health:
        return _require_manual_action(
            db,
            remediation,
            "Replacement twin is not ready for revalidation; fresh health evidence is required before revalidation can run.",
        )

    initial_validation = (
        db.query(Validation)
        .filter(
            Validation.vulnerability_id == remediation.vulnerability_id,
            Validation.phase == "initial",
        )
        .order_by(Validation.created_at.desc())
        .first()
    )
    if initial_validation is None:
        return _require_manual_action(
            db,
            remediation,
            "No initial validation found for this vulnerability; cannot compare "
            "before/after without a baseline.",
        )

    exploit: Optional[Exploit] = None
    if initial_validation.exploit_id is not None:
        exploit = db.query(Exploit).filter(Exploit.id == initial_validation.exploit_id).first()
    if exploit is None:
        return _require_manual_action(
            db,
            remediation,
            "Could not resolve the original exploit used for the initial validation; "
            "cannot run the same exploit for revalidation.",
        )

    remediation.status = remediation_status.REVALIDATING
    db.add(remediation)
    db.commit()
    db.refresh(remediation)

    
    engine = RevalidationEngine()

    try:
        summary = await engine.run(
            db, exploit, twin, initial_validation, remediation
        )

        comparison = build_before_after_comparison(
            initial_validation, summary.revalidation, summary.result
        )

        remediation.verification_score = summary.revalidation_score
        remediation.evidence = {
            **(remediation.evidence or {}),
            "before_after": comparison,
            "revalidation_comparison": summary.comparison,
            "revalidation_outcome": summary.result,
        }

        if summary.result == "resolved":
            remediation.status = remediation_status.VERIFIED
            remediation.verified_at = datetime.now(timezone.utc)

        elif summary.result == "still_vulnerable":
            remediation.status = remediation_status.FAILED
            remediation.verified_at = None

        else:
            remediation.status = remediation_status.MANUAL_ACTION_REQUIRED
            remediation.verified_at = None
            remediation.evidence["manual_action_reason"] = (
                "Revalidation was inconclusive. Human review and further "
                "verification are required before remediation can be "
                "classified as resolved or still vulnerable."
            )

        db.add(remediation)
        db.commit()
        db.refresh(remediation)

        logger.info(
            "Remediation %s revalidation complete: outcome=%s status=%s",
            remediation_id,
            summary.result,
            remediation.status,
        )
        return remediation

    except Exception as exc:
        # Recover the transaction before trying to persist the failure state.
        logger.exception(
            "Revalidation failed unexpectedly for remediation %s",
            remediation_id,
        )
        db.rollback()

        # Reload the row because rollback may expire ORM attributes.
        remediation = (
            db.query(Remediation)
            .filter(Remediation.id == remediation_id)
            .first()
        )

        if remediation is None:
            raise

        remediation.status = remediation_status.MANUAL_ACTION_REQUIRED
        remediation.verified_at = None
        remediation.evidence = {
            **(remediation.evidence or {}),
            "manual_action_reason": (
                "Revalidation encountered an unexpected error. "
                "Review the failure and rerun verification before "
                "classifying the remediation as resolved."
            ),
            "revalidation_error": type(exc).__name__,
        }

        db.add(remediation)
        db.commit()
        db.refresh(remediation)
        return remediation



def _require_manual_action(db: Session, remediation: Remediation, reason: str) -> Remediation:
    remediation.status = remediation_status.MANUAL_ACTION_REQUIRED
    remediation.evidence = {
        **(remediation.evidence or {}),
        "manual_action_reason": reason,
    }
    db.add(remediation)
    db.commit()
    db.refresh(remediation)
    logger.warning("Remediation %s requires manual action: %s", remediation.id, reason)
    return remediation
