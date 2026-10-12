"""
ClosedLoopOrchestrator.

Scope note (important, read before extending): this orchestrator currently
runs exactly the portion of the AutoSecTwin pipeline that has a real,
working implementation today:

    provision Twin -> resolve mapped Exploit -> run ValidationOrchestrator
    -> generate a Recommendation if validated

It deliberately STOPS at the human-approval gate. It does not approve,
remediate, or revalidate anything itself -- "Do not bypass approval
because the vulnerability has a high score" applies here too. Once the
real PatchExecutor/RevalidationEngine wiring lands, this class is the
natural place to extend the run() method to continue past approval --
until then, calling it as if it does that would be exactly the kind of
false "verified"/"remediated" claim this project is trying to eliminate.

For the same reason, this orchestrator does NOT destroy the Twin it
provisions, even though ORCHESTRATION_DESTROY_TWIN_AFTER_RUN defaults to
True. That flag describes teardown after the *entire* workflow (through
remediation/revalidation) completes -- destroying the Twin right after
validation would delete the exact target a human approver needs to
inspect and a later remediation needs to act on. Teardown is wired in once
that later stage exists; until then the Twin is left running and its id is
returned in the summary so it can be found and cleaned up manually if the
run doesn't proceed to remediation.
"""

from __future__ import annotations

import logging
from typing import Any

from sqlalchemy.orm import Session

from core.config import settings
from core.exceptions import ASDEError
from database.models.exploit import Exploit
from services.orchestration.validation_orchestrator import ValidationOrchestrator
from services.recommendation.recommendation_engine import RecommendationEngine
from services.twin_provisioning_service import TwinProvisioningService

logger = logging.getLogger(__name__)


class ClosedLoopOrchestrationError(ASDEError):
    """Raised when the closed loop cannot proceed (e.g. no exploit mapped)."""

    def __init__(self, message: str) -> None:
        super().__init__(message, code="CLOSED_LOOP_ERROR", status_code=422)


class ClosedLoopOrchestrator:
    """Coordinates Twin provisioning through recommendation generation."""

    def __init__(
        self,
        db: Session,
        provisioning_service: TwinProvisioningService | None = None,
        validation_orchestrator: ValidationOrchestrator | None = None,
        recommendation_engine: RecommendationEngine | None = None,
    ) -> None:
        self.db = db
        self.provisioning_service = provisioning_service or TwinProvisioningService(db)
        self.validation_orchestrator = validation_orchestrator or ValidationOrchestrator()
        self.recommendation_engine = recommendation_engine or RecommendationEngine(db)

    def _resolve_exploit(self, vulnerability_id: int) -> Exploit:
        """Pick the exploit mapped to this vulnerability with the highest
        reliability_score. Does not create one -- exploit discovery/mapping
        is a separate concern (POST /exploits) from orchestrating a run.
        """

        exploit = (
            self.db.query(Exploit)
            .filter(Exploit.vulnerability_id == vulnerability_id)
            .order_by(Exploit.reliability_score.desc(), Exploit.id.asc())
            .first()
        )

        if exploit is None:
            raise ClosedLoopOrchestrationError(
                f"No Exploit is mapped to vulnerability {vulnerability_id}. "
                "Create one via POST /exploits before running orchestration."
            )

        return exploit

    async def run(
        self,
        vulnerability_id: int,
        ttl_seconds: int | None = None,
    ) -> dict[str, Any]:
        """Run provisioning -> validation -> recommendation for one
        vulnerability. Returns a JSON-serializable summary. Raises
        ClosedLoopOrchestrationError (or lets underlying HTTPException/
        RuntimeError propagate) on failure -- the caller (the Celery task
        or the inline BackgroundTasks runner) is responsible for catching
        this and recording it on the OrchestrationJob row.
        """

        logger.info("Closed loop run starting for vulnerability %s", vulnerability_id)

        exploit = self._resolve_exploit(vulnerability_id)

        twin = await self.provisioning_service.provision(
            vulnerability_id, ttl_seconds=ttl_seconds
        )
        twin = await self.provisioning_service.wait_until_ready(twin)

        result = await self.validation_orchestrator.validate(self.db, exploit, twin)

        summary: dict[str, Any] = {
            "vulnerability_id": vulnerability_id,
            "twin_id": twin.id,
            "twin_destroyed": False,
            "exploit_id": exploit.id,
            "validation_id": result.validation.id,
            "validation_status": result.validation.status,
            "validation_score": result.validation.validation_score,
            "readiness_ready": result.readiness.ready,
        }

        if not result.readiness.ready:
            summary["next_step"] = "not_ready_for_execution"
            summary["readiness_reasons"] = result.readiness.reasons
            logger.info(
                "Closed loop run for vulnerability %s stopped: readiness gate failed.",
                vulnerability_id,
            )
            return summary

        if result.validation.status == "validated":
            recommendation = self.recommendation_engine.generate(
                vulnerability_id=vulnerability_id,
                recommendation_type="patch",
            )
            summary["recommendation_id"] = recommendation.id
            summary["next_step"] = "awaiting_human_approval"
        else:
            summary["next_step"] = "not_validated_no_recommendation_generated"

        logger.info(
            "Closed loop run for vulnerability %s completed: %s",
            vulnerability_id,
            summary["next_step"],
        )

        return summary
