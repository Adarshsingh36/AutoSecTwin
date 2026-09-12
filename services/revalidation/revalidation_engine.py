import logging
from dataclasses import dataclass
from typing import Any

from sqlalchemy.orm import Session

from database.models.exploit import Exploit
from database.models.remediation import Remediation
from database.models.twin import Twin
from database.models.validation import Validation

from services.orchestration.validation_orchestrator import (
    OrchestrationResult,
    ValidationOrchestrator,
)

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class RevalidationSummary:
    """Comparison between the initial and post-remediation validation."""

    result: str  # "resolved" | "still_vulnerable" | "inconclusive"
    initial_validation: Validation
    revalidation: Validation
    initial_score: float
    revalidation_score: float
    improvement: float
    comparison: str


class RevalidationEngine:
    """Re-runs the same controlled validation after remediation and
    determines whether the vulnerability was actually resolved.

    Preserves the legacy ``verify(validation_score)`` heuristic method for
    backward compatibility with the existing ``/remediations/{id}/revalidate``
    endpoint, and adds ``run(...)``, which performs a *real* re-validation
    against the Digital Twin via ``ValidationOrchestrator`` and persists both
    before/after evidence using the ``Validation`` table's ``phase`` column
    (no duplicate table, per the "reuse the existing model" requirement).
    """

    RESOLVED_THRESHOLD = 0.35  # revalidation score below this => resolved
    IMPROVEMENT_THRESHOLD = 0.30  # meaningful score drop even if not fully resolved

    def __init__(self, orchestrator: ValidationOrchestrator | None = None) -> None:
        self.orchestrator = orchestrator or ValidationOrchestrator()

    def verify(self, validation_score: float, evidence: dict[str, Any] | None = None) -> tuple[str, float, dict[str, Any]]:
        """Legacy heuristic verification from a bare residual score."""

        evidence = evidence or {}
        residual = max(0.0, min(1.0, validation_score))
        verification_score = 1.0 - residual
        status = "verified" if verification_score >= 0.75 else "partial" if verification_score >= 0.45 else "failed"
        return status, verification_score, {"residual_validation_score": residual, **evidence}

    async def run(
        self,
        db: Session,
        exploit: Exploit,
        twin: Twin,
        initial_validation: Validation,
        remediation: Remediation,
    ) -> RevalidationSummary:
        """Re-execute the same controlled validation against the Twin and
        compare the outcome to the pre-remediation validation.
        """

        logger.info(
            "Revalidation started: exploit=%s twin=%s remediation=%s",
            exploit.id,
            twin.id,
            remediation.id,
        )

        result: OrchestrationResult = await self.orchestrator.validate(db, exploit, twin)
        revalidation = result.validation
        revalidation.phase = "revalidation"
        db.commit()
        db.refresh(revalidation)

        initial_score = float(initial_validation.validation_score or 0.0)
        revalidation_score = float(revalidation.validation_score or 0.0)
        improvement = initial_score - revalidation_score

        if revalidation.status != "validated" and revalidation_score <= self.RESOLVED_THRESHOLD:
            outcome = "resolved"
        elif revalidation.status == "validated" and improvement < self.IMPROVEMENT_THRESHOLD:
            outcome = "still_vulnerable"
        else:
            outcome = "inconclusive"

        comparison = (
            f"Initial score: {initial_score:.2f} -> Post-remediation score: {revalidation_score:.2f} "
            f"(improvement={improvement:.2f}). Result: {outcome.upper()}"
        )

        logger.info(
            "Revalidation completed: exploit=%s twin=%s outcome=%s (%s)",
            exploit.id,
            twin.id,
            outcome,
            comparison,
        )

        return RevalidationSummary(
            result=outcome,
            initial_validation=initial_validation,
            revalidation=revalidation,
            initial_score=initial_score,
            revalidation_score=revalidation_score,
            improvement=improvement,
            comparison=comparison,
        )
