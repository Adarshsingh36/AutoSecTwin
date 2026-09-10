from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from database.models.exploit import Exploit
from database.models.twin import Twin
from database.models.validation import Validation

from services.orchestration.exploit_executor import (
    ExploitExecutor,
    ExploitExecutionResult,
)
from services.orchestration.exploit_mapper import ExploitMapper
from services.orchestration.exploit_readiness import (
    ExploitReadiness,
    ExploitReadinessChecker,
)
from services.orchestration.module_inspector import (
    MetasploitModuleInspector,
)
from services.validation.validation_engine import ValidationEngine


@dataclass(frozen=True)
class OrchestrationResult:
    validation: Validation
    execution: ExploitExecutionResult | None
    readiness: ExploitReadiness


class ValidationOrchestrator:
    """
    Coordinates the controlled Digital Twin validation workflow.

    Flow:

        Exploit
          ↓
        Module mapping
          ↓
        Metasploit inspection
          ↓
        Readiness gate
          ↓
        Metasploit execution
          ↓
        Evidence collection
          ↓
        Evidence analysis
          ↓
        Validation persistence
    """

    def __init__(
        self,
        executor: ExploitExecutor | None = None,
        validation_engine: ValidationEngine | None = None,
        inspector: MetasploitModuleInspector | None = None,
        readiness_checker: ExploitReadinessChecker | None = None,
        mapper: ExploitMapper | None = None,
    ) -> None:

        self.executor = executor or ExploitExecutor()

        self.validation_engine = (
            validation_engine or ValidationEngine()
        )

        self.inspector = (
            inspector
            or MetasploitModuleInspector(
                rpc_client=self.executor.rpc_client
            )
        )

        self.readiness_checker = (
            readiness_checker or ExploitReadinessChecker()
        )

        self.mapper = mapper or ExploitMapper()

    async def validate(
        self,
        db: Session,
        exploit: Exploit,
        twin: Twin,
    ) -> OrchestrationResult:
        """
        Execute the complete controlled validation workflow.

        Exploitation is performed only against the supplied
        Digital Twin.
        """

        started_at = datetime.now(timezone.utc)

        # ==================================================
        # 1. MAP EXPLOIT
        # ==================================================

        mapping = self.mapper.map(exploit)

        # ==================================================
        # 2. INSPECT METASPLOIT MODULE
        # ==================================================

        inspection = await self.inspector.inspect(
            module_type=mapping.module_type,
            module_name=mapping.module_name,
        )

        # ==================================================
        # 3. READINESS CHECK
        # ==================================================

        supplied_options: dict[str, Any] = (
            mapping.metadata.get("options", {})
            if mapping.metadata
            else {}
        )

        readiness = self.readiness_checker.check(
            inspection=inspection,
            twin=twin,
            supplied_options=supplied_options,
        )

        # ==================================================
        # 4. BLOCK IF NOT READY
        # ==================================================

        if not readiness.ready:

            completed_at = datetime.now(timezone.utc)

            validation = Validation(
                vulnerability_id=exploit.vulnerability_id,
                exploit_id=exploit.id,
                twin_id=twin.id,
                status="failed",
                validation_score=0.0,
                analysis=(
                    "Validation blocked before execution. "
                    + " ".join(readiness.reasons)
                ),
                evidence={
                    "stage": "readiness",
                    "ready": False,
                    "reasons": readiness.reasons,
                    "required_options": readiness.required_options,
                    "missing_options": readiness.missing_options,
                    "target": readiness.target,
                    "module_type": mapping.module_type,
                    "module_name": mapping.module_name,
                },
                started_at=started_at,
                completed_at=completed_at,
            )

            db.add(validation)
            db.commit()
            db.refresh(validation)

            return OrchestrationResult(
                validation=validation,
                execution=None,
                readiness=readiness,
            )

        # ==================================================
        # 5. EXECUTE AGAINST DIGITAL TWIN
        # ==================================================

        execution = await self.executor.execute(
            exploit=exploit,
            twin=twin,
        )

        # ==================================================
        # 6. ANALYZE EVIDENCE
        # ==================================================

        status, score, analysis = (
            self.validation_engine.analyze(
                execution.evidence
            )
        )

        completed_at = datetime.now(timezone.utc)

        # ==================================================
        # 7. PERSIST VALIDATION
        # ==================================================

        validation = Validation(
            vulnerability_id=exploit.vulnerability_id,
            exploit_id=exploit.id,
            twin_id=twin.id,
            status=status,
            validation_score=score,
            analysis=analysis,
            evidence=execution.evidence,
            started_at=started_at,
            completed_at=completed_at,
        )

        db.add(validation)
        db.commit()
        db.refresh(validation)

        return OrchestrationResult(
            validation=validation,
            execution=execution,
            readiness=readiness,
        )