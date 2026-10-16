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
import json
from typing import Any

from sqlalchemy.orm import Session

from core.config import settings
from core.exceptions import ASDEError
from database.models.exploit import Exploit
from database.models.vulnerability import Vulnerability
from services.approval.workflow import request_approval, request_recommendation_review
from services.orchestration.validation_orchestrator import ValidationOrchestrator
from services.recommendation.recommendation_engine import RecommendationEngine
from services.reporting.workflow_report_service import create_validation_report
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
        fixed_version: str | None = None,
    ) -> dict[str, Any]:
        """Run provisioning -> validation -> report/recommendation/approval
        preparation for one vulnerability. Returns a JSON-serializable summary. Raises
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
        fixed_version = fixed_version.strip() if fixed_version else None

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
        recommendation = None
        approval = None

        if not result.readiness.ready:
            summary["next_step"] = "not_ready_for_execution"
            summary["readiness_reasons"] = result.readiness.reasons
            logger.info(
                "Closed loop run for vulnerability %s stopped: readiness gate failed.",
                vulnerability_id,
            )
        elif result.validation.status == "validated":
            recommendation = self.recommendation_engine.generate(
                vulnerability_id=vulnerability_id,
                recommendation_type="patch",
            )
            summary["recommendation_id"] = recommendation.id
            report = create_validation_report(
                self.db,
                vulnerability=self.db.get(Vulnerability, vulnerability_id),
                validation=result.validation,
                exploit=exploit,
                twin=twin,
                recommendation=recommendation,
                evidence_source=(
                    "simulated_twin_validation"
                    if settings.MOCK_MODE
                    else "controlled_twin_validation"
                ),
            )
            if fixed_version:
                approval = request_approval(
                    self.db,
                    vulnerability_id=vulnerability_id,
                    target_twin_id=twin.id,
                    fixed_version=fixed_version,
                    recommendation_id=recommendation.id,
                )
                summary["next_step"] = "awaiting_human_approval"
            else:
                report_body = json.loads(report.content)
                report_findings = report_body.get("findings", {})
                approval = request_recommendation_review(
                    self.db,
                    vulnerability_id=vulnerability_id,
                    recommendation_id=recommendation.id,
                    report_id=report.id,
                    review_package={
                        "vulnerability": {
                            "id": vulnerability_id,
                            "cve_id": getattr(
                                self.db.get(Vulnerability, vulnerability_id), "cve_id", None
                            ),
                            "title": getattr(
                                self.db.get(Vulnerability, vulnerability_id), "title", None
                            ),
                        },
                        "plain_language": report_findings.get("plain_language", {}),
                        "validation_status": result.validation.status,
                        "findings": (result.validation.evidence or {}).get("findings", []),
                        "recommendation": {
                            "id": recommendation.id,
                            "title": recommendation.title,
                            "content": recommendation.content,
                        },
                        "report_id": report.id,
                        "limitations": [
                            "This review accepts or rejects the recommendation only; it does not deploy a patch.",
                            "A separate approval tied to a Digital Twin and fixed version is required for deployment.",
                        ],
                    },
                )
                summary["next_step"] = "awaiting_human_review"
        else:
            summary["next_step"] = "not_validated_no_recommendation_generated"

        if result.readiness.ready and result.validation.status == "validated":
            summary["report_id"] = report.id
        else:
            report = create_validation_report(
                self.db,
                vulnerability=self.db.get(Vulnerability, vulnerability_id),
                validation=result.validation,
                exploit=exploit,
                twin=twin,
                evidence_source=(
                    "simulated_twin_validation"
                    if settings.MOCK_MODE
                    else "controlled_twin_validation"
                ),
            )
            summary["report_id"] = report.id
        if approval is not None:
            review_package = dict((approval.context or {}).get("review_package") or {})
            review_package["report_id"] = report.id
            approval.context = {
                **(approval.context or {}),
                "report_id": report.id,
                "validation_report_id": report.id,
                "review_package": review_package,
            }
            self.db.commit()
            summary["approval_id"] = approval.id
            summary["review_url"] = f"/approvals/{approval.id}/review"

        logger.info(
            "Closed loop run for vulnerability %s completed: %s",
            vulnerability_id,
            summary["next_step"],
        )

        return summary
