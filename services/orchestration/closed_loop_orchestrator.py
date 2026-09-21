import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from core.config import settings
from database.models.audit import Audit
from database.models.exploit import Exploit
from database.models.learning_event import LearningEvent
from database.models.orchestration_job import OrchestrationJob
from database.models.remediation import Remediation
from database.models.report import Report
from database.models.twin import Twin
from database.models.validation import Validation
from database.models.vulnerability import Vulnerability

from services.exploitability.predictor import ExploitabilityPredictionEngine
from services.orchestration.validation_orchestrator import ValidationOrchestrator
from services.remediation.remediation_engine import RemediationEngine
from services.reporting.report_generator import ReportGenerator
from services.revalidation.revalidation_engine import RevalidationEngine
from services.twin_provisioning_service import TwinProvisioningService

logger = logging.getLogger(__name__)


class OrchestrationError(Exception):
    """Raised when the closed loop cannot continue and must stop cleanly."""

    def __init__(self, stage: str, message: str) -> None:
        self.stage = stage
        self.message = message
        super().__init__(f"[{stage}] {message}")


@dataclass
class ClosedLoopResult:
    """Final, persisted outcome of a single closed-loop run."""

    final_status: str
    vulnerability_id: int
    twin_id: int | None = None
    exploit_id: int | None = None
    exploitability_probability: float | None = None
    initial_validation_id: int | None = None
    remediation_id: int | None = None
    revalidation_id: int | None = None
    report_id: int | None = None
    summary: dict[str, Any] = field(default_factory=dict)


class ClosedLoopOrchestrator:
    """Coordinates the full AutoSecTwin lifecycle for a single vulnerability:

        Vulnerability -> Exploitability Prediction -> Exploit Selection ->
        Digital Twin Provisioning -> Twin Readiness -> Controlled Validation
        -> Remediation -> Revalidation -> Report -> Learning Feedback ->
        Twin Cleanup

    Deliberately does *not* implement each stage itself -- it wires together
    the dedicated services (``TwinProvisioningService``,
    ``ValidationOrchestrator``, ``RemediationEngine``, ``RevalidationEngine``,
    ``ReportGenerator``) that already own that logic, updating an
    ``OrchestrationJob`` row after every stage so the run is safely
    resumable/observable from the API layer without blocking the request
    thread.
    """

    def __init__(
        self,
        twin_service_factory=TwinProvisioningService,
        validation_orchestrator: ValidationOrchestrator | None = None,
        remediation_engine: RemediationEngine | None = None,
        revalidation_engine: RevalidationEngine | None = None,
        report_generator: ReportGenerator | None = None,
        predictor: ExploitabilityPredictionEngine | None = None,
    ) -> None:
        self.twin_service_factory = twin_service_factory
        self.validation_orchestrator = validation_orchestrator or ValidationOrchestrator()
        self.remediation_engine = remediation_engine or RemediationEngine()
        self.revalidation_engine = revalidation_engine or RevalidationEngine(self.validation_orchestrator)
        self.report_generator = report_generator or ReportGenerator()
        self._predictor: ExploitabilityPredictionEngine | None = predictor

    @property
    def predictor(self) -> ExploitabilityPredictionEngine:
        # Lazily constructed: loading the XGBoost artifact has real cost and
        # some test/dev environments intentionally don't ship it.
        if self._predictor is None:
            self._predictor = ExploitabilityPredictionEngine()
        return self._predictor

    async def run(
        self,
        db: Session,
        job: OrchestrationJob,
        auto_apply_remediation: bool | None = None,
        destroy_twin_after: bool | None = None,
    ) -> ClosedLoopResult:
        """Execute the full closed loop for ``job.vulnerability_id``.

        Every stage transition is persisted onto ``job`` immediately so a
        concurrent ``GET /orchestration/{job_id}`` always reflects real
        progress, and every failure leaves the job (and any partial
        evidence already persisted) in a consistent, inspectable state
        rather than raising past the background task boundary.
        """

        auto_apply_remediation = (
            settings.REMEDIATION_AUTO_APPLY if auto_apply_remediation is None else auto_apply_remediation
        )
        destroy_twin_after = (
            settings.ORCHESTRATION_DESTROY_TWIN_AFTER_RUN if destroy_twin_after is None else destroy_twin_after
        )

        twin: Twin | None = None
        exploit: Exploit | None = None
        initial_validation: Validation | None = None
        remediation: Remediation | None = None
        revalidation_summary = None
        exploitability_probability: float | None = None

        job.status = "running"
        job.started_at = datetime.now(timezone.utc)
        job.mock_mode = "true" if settings.MOCK_MODE else "false"
        self._advance(db, job, "assessment", 5, "Loading vulnerability and running exploitability prediction.")

        try:
            vulnerability = self._load_vulnerability(db, job.vulnerability_id)
            self._audit(db, "workflow_started", "vulnerability", vulnerability.id, {"job_id": job.job_id})

            # ------------------------------------------------------------
            # 1-2. Exploitability prediction
            # ------------------------------------------------------------
            exploitability_probability = self._predict_exploitability(vulnerability)
            self._audit(
                db,
                "vulnerability_assessed",
                "vulnerability",
                vulnerability.id,
                {"exploitability_probability": exploitability_probability},
            )

            # ------------------------------------------------------------
            # 3. Exploit candidate selection
            # ------------------------------------------------------------
            self._advance(db, job, "exploit_selection", 15, "Selecting best mapped exploit candidate.")
            exploit = self._select_exploit(db, vulnerability)
            self._audit(db, "exploit_selected", "exploit", exploit.id, {"module_name": exploit.module_name})

            # ------------------------------------------------------------
            # 4-5. Digital Twin provisioning + readiness
            # ------------------------------------------------------------
            self._advance(db, job, "twin_provisioning", 25, "Provisioning isolated Digital Twin.")
            twin_service = self.twin_service_factory(db)
            twin = await twin_service.provision(vulnerability_id=vulnerability.id)
            self._audit(db, "twin_requested", "twin", twin.id, {"provider": twin.provider})

            self._advance(db, job, "twin_ready", 35, "Waiting for Digital Twin readiness.")
            twin = await twin_service.wait_until_ready(twin)
            self._enforce_twin_boundary(twin)
            self._audit(db, "twin_ready", "twin", twin.id, {"health": twin.health})

            # ------------------------------------------------------------
            # 6-9. Module inspection, readiness, execution, evidence, persist
            # ------------------------------------------------------------
            self._advance(db, job, "validation", 50, "Inspecting module and executing controlled validation.")
            orchestration_result = await self.validation_orchestrator.validate(db, exploit, twin)
            initial_validation = orchestration_result.validation
            initial_validation.phase = "initial"
            db.commit()
            db.refresh(initial_validation)
            self._audit(
                db,
                "validation_completed",
                "validation",
                initial_validation.id,
                {"status": initial_validation.status, "score": initial_validation.validation_score},
            )

            self._advance(db, job, "analysis", 60, f"Validation status: {initial_validation.status}.")

            # ------------------------------------------------------------
            # 10-13. Remediation recommendation / application / revalidation
            # ------------------------------------------------------------
            if initial_validation.status == "validated":
                self._advance(db, job, "remediation", 70, "Generating and applying remediation.")
                remediation = self.remediation_engine.recommend(db, vulnerability)
                remediation = self.remediation_engine.plan(db, remediation)
                self._audit(db, "remediation_started", "remediation", remediation.id, {"action": remediation.action})

                if auto_apply_remediation:
                    remediation = self.remediation_engine.apply(db, remediation, twin)

                    if remediation.status == "applied":
                        # Reflect the applied control on the twin so a
                        # revalidation run can observe the change (in
                        # MOCK_MODE this drives the simulated evidence).
                        twin.health = "remediated"
                        twin.status = "revalidating"
                        db.commit()
                        db.refresh(twin)

                        self._advance(db, job, "revalidation", 80, "Revalidating against remediated Digital Twin.")
                        revalidation_summary = await self.revalidation_engine.run(
                            db, exploit, twin, initial_validation, remediation
                        )
                        self._audit(
                            db,
                            "revalidation_completed",
                            "validation",
                            revalidation_summary.revalidation.id,
                            {"result": revalidation_summary.result, "comparison": revalidation_summary.comparison},
                        )

                        if revalidation_summary.result == "resolved":
                            remediation = self.remediation_engine.mark_verified(
                                db, remediation, revalidation_summary.revalidation_score
                            )
                        elif revalidation_summary.result == "still_vulnerable":
                            remediation = self.remediation_engine.mark_failed(
                                db, remediation, "Vulnerability still validated after remediation."
                            )
                    self._audit(db, "remediation_completed", "remediation", remediation.id, {"status": remediation.status})
            else:
                self._advance(
                    db,
                    job,
                    "remediation",
                    70,
                    f"Skipping remediation: initial validation was '{initial_validation.status}', not 'validated'.",
                )

            # ------------------------------------------------------------
            # 14. Final report
            # ------------------------------------------------------------
            self._advance(db, job, "report_generation", 90, "Generating final closed-loop report.")
            final_status = self._determine_final_status(initial_validation, remediation, revalidation_summary)
            audit_trail = self._recent_audit_trail(db, [vulnerability.id, twin.id if twin else None])

            content = self.report_generator.generate_closed_loop_report(
                title=f"AutoSecTwin Closed-Loop Report: {vulnerability.cve_id}",
                vulnerability=vulnerability,
                twin=twin,
                exploit=exploit,
                initial_validation=initial_validation,
                remediation=remediation,
                revalidation=revalidation_summary.revalidation if revalidation_summary else None,
                revalidation_comparison=revalidation_summary.comparison if revalidation_summary else None,
                final_status=final_status,
                audit_trail=audit_trail,
                exploitability_probability=exploitability_probability,
                mock_mode=settings.MOCK_MODE,
            )
            report = Report(
                vulnerability_id=vulnerability.id,
                report_type="closed_loop",
                title=f"AutoSecTwin Closed-Loop Report: {vulnerability.cve_id}",
                content=content,
                format="json",
                metadata_json={"job_id": job.job_id},
            )
            db.add(report)
            db.commit()
            db.refresh(report)
            self._audit(db, "report_generated", "report", report.id, {"final_status": final_status})

            # ------------------------------------------------------------
            # 15-16. Learning feedback
            # ------------------------------------------------------------
            self._record_learning_event(
                db,
                vulnerability,
                exploitability_probability,
                initial_validation,
                remediation,
                revalidation_summary,
            )

            # ------------------------------------------------------------
            # 17. Twin cleanup
            # ------------------------------------------------------------
            if twin is not None and destroy_twin_after:
                self._advance(db, job, "cleanup", 95, "Destroying Digital Twin.")
                try:
                    await twin_service.destroy(twin.id)
                    self._audit(db, "twin_destroyed", "twin", twin.id, {})
                except Exception as exc:  # noqa: BLE001 - best-effort cleanup
                    logger.warning("Twin cleanup failed for twin %s: %s", twin.id, exc)

            result = ClosedLoopResult(
                final_status=final_status,
                vulnerability_id=vulnerability.id,
                twin_id=twin.id if twin else None,
                exploit_id=exploit.id if exploit else None,
                exploitability_probability=exploitability_probability,
                initial_validation_id=initial_validation.id if initial_validation else None,
                remediation_id=remediation.id if remediation else None,
                revalidation_id=revalidation_summary.revalidation.id if revalidation_summary else None,
                report_id=report.id,
                summary={
                    "cve_id": vulnerability.cve_id,
                    "initial_validation_status": initial_validation.status if initial_validation else None,
                    "remediation_status": remediation.status if remediation else None,
                    "revalidation_result": revalidation_summary.result if revalidation_summary else None,
                    "comparison": revalidation_summary.comparison if revalidation_summary else None,
                },
            )

            job.status = "completed"
            job.stage = "completed"
            job.progress = 100
            job.message = f"Workflow completed: {final_status}"
            job.result_json = result.__dict__
            job.completed_at = datetime.now(timezone.utc)
            db.commit()

            return result

        except OrchestrationError as exc:
            self._fail_job(db, job, exc.stage, exc.message)
            self._audit(db, "workflow_failed", "vulnerability", job.vulnerability_id, {"stage": exc.stage, "reason": exc.message})
            raise
        except Exception as exc:  # noqa: BLE001 - convert to a clean job failure
            logger.exception("Closed-loop orchestration failed unexpectedly")
            self._fail_job(db, job, job.stage, str(exc))
            self._audit(db, "workflow_failed", "vulnerability", job.vulnerability_id, {"stage": job.stage, "reason": str(exc)})
            raise

    # ----------------------------------------------------------------
    # Stage helpers
    # ----------------------------------------------------------------

    def _load_vulnerability(self, db: Session, vulnerability_id: int) -> Vulnerability:
        vulnerability = db.get(Vulnerability, vulnerability_id)
        if vulnerability is None:
            raise OrchestrationError("assessment", f"Vulnerability {vulnerability_id} not found.")
        return vulnerability

    def _predict_exploitability(self, vulnerability: Vulnerability) -> float:
        try:
            return self.predictor.predict(vulnerability)
        except Exception as exc:  # noqa: BLE001 - model failures must not crash the loop
            raise OrchestrationError(
                "assessment", f"Exploitability model failed to produce a prediction: {exc}"
            ) from exc

    def _select_exploit(self, db: Session, vulnerability: Vulnerability) -> Exploit:
        exploit = (
            db.query(Exploit)
            .filter(Exploit.vulnerability_id == vulnerability.id)
            .filter(Exploit.module_name.isnot(None))
            .order_by(Exploit.reliability_score.desc())
            .first()
        )
        if exploit is None:
            raise OrchestrationError(
                "exploit_selection",
                f"No mapped Metasploit-ready exploit candidate exists for vulnerability {vulnerability.id}. "
                "Add an Exploit row with a module_name before running the closed loop.",
            )
        return exploit

    def _enforce_twin_boundary(self, twin: Twin) -> None:
        """Refuse to continue unless the target resolves to a managed Twin.

        This is the safety boundary required by the project: validation
        (and therefore exploitation) may only ever run against an isolated
        Digital Twin created by ``TwinProvisioningService``, never directly
        against arbitrary infrastructure.
        """

        if not settings.ENFORCE_DIGITAL_TWIN_BOUNDARY:
            return
        if not (twin.ip_address or twin.endpoint):
            raise OrchestrationError(
                "twin_ready", f"Twin {twin.id} has no resolvable target; refusing to execute exploit."
            )

    def _determine_final_status(
        self,
        initial_validation: Validation | None,
        remediation: Remediation | None,
        revalidation_summary,
    ) -> str:
        if initial_validation is None:
            return "unknown"
        if initial_validation.status != "validated":
            return "not_exploitable"
        if revalidation_summary is None:
            return "validated_pending_remediation"
        if revalidation_summary.result == "resolved":
            return "remediated"
        if revalidation_summary.result == "still_vulnerable":
            return "still_vulnerable"
        return "inconclusive"

    def _record_learning_event(
        self,
        db: Session,
        vulnerability: Vulnerability,
        exploitability_probability: float | None,
        initial_validation: Validation | None,
        remediation: Remediation | None,
        revalidation_summary,
    ) -> None:
        event = LearningEvent(
            event_type="closed_loop_outcome",
            source="closed_loop_orchestrator",
            label=initial_validation.status if initial_validation else None,
            confidence_before=exploitability_probability,
            confidence_after=revalidation_summary.revalidation_score if revalidation_summary else None,
            payload={
                "vulnerability_id": vulnerability.id,
                "cve_id": vulnerability.cve_id,
                "predicted_exploitability": exploitability_probability,
                "actual_validation_result": initial_validation.status if initial_validation else None,
                "remediation_status": remediation.status if remediation else None,
                "revalidation_result": revalidation_summary.result if revalidation_summary else None,
            },
            notes="Recorded by ClosedLoopOrchestrator for future model retraining/calibration.",
        )
        db.add(event)
        db.commit()

    def _recent_audit_trail(self, db: Session, entity_ids: list[int | None]) -> list[dict[str, Any]]:
        ids = [i for i in entity_ids if i is not None]
        if not ids:
            return []
        rows = (
            db.query(Audit)
            .filter(Audit.entity_id.in_(ids))
            .order_by(Audit.id.asc())
            .all()
        )
        return [
            {
                "action": row.action,
                "entity_type": row.entity_type,
                "entity_id": row.entity_id,
                "details": row.details,
                "created_at": row.created_at,
            }
            for row in rows
        ]

    def _audit(self, db: Session, action: str, entity_type: str, entity_id: int | None, details: dict[str, Any]) -> None:
        db.add(
            Audit(
                actor="closed_loop_orchestrator",
                action=action,
                entity_type=entity_type,
                entity_id=entity_id,
                details=details,
            )
        )
        db.commit()

    def _advance(self, db: Session, job: OrchestrationJob, stage: str, progress: int, message: str) -> None:
        job.stage = stage
        job.progress = progress
        job.message = message
        db.commit()
        logger.info("Job %s -> stage=%s progress=%s message=%s", job.job_id, stage, progress, message)

    def _fail_job(self, db: Session, job: OrchestrationJob, stage: str, message: str) -> None:
        job.status = "failed"
        job.stage = stage
        job.error = message
        job.message = f"Failed at stage '{stage}': {message}"
        job.completed_at = datetime.now(timezone.utc)
        db.commit()
        logger.error("Job %s failed at stage=%s: %s", job.job_id, stage, message)
