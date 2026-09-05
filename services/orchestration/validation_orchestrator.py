from dataclasses import dataclass
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
        Metasploit module inspection
          ↓
        Readiness check
          ↓
        Execution against Digital Twin
          ↓
        Evidence analysis
          ↓
        Persist validation
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
            inspector or MetasploitModuleInspector(
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
        Run the complete controlled validation workflow.
        """

        # --------------------------------------------------
        # 1. Resolve exploit → Metasploit module
        # --------------------------------------------------

        mapping = self.mapper.map(exploit)

        # --------------------------------------------------
        # 2. Inspect module
        # --------------------------------------------------

        inspection = await self.inspector.inspect(
            module_type=mapping.module_type,
            module_name=mapping.module_name,
        )

        # --------------------------------------------------
        # 3. Check execution readiness
        # --------------------------------------------------

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

        # --------------------------------------------------
        # 4. Do NOT execute if readiness gate fails
        # --------------------------------------------------

        if not readiness.ready:

            validation = Validation(
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
            )

            db.add(validation)
            db.commit()
            db.refresh(validation)

            return OrchestrationResult(
                validation=validation,
                execution=None,
                readiness=readiness,
            )

        # --------------------------------------------------
        # 5. Execute against Digital Twin
        # --------------------------------------------------

        execution = await self.executor.execute(
            exploit=exploit,
            twin=twin,
        )

        # --------------------------------------------------
        # 6. Analyze evidence
        # --------------------------------------------------

        status, score, analysis = (
            self.validation_engine.analyze(
                execution.evidence
            )
        )

        # --------------------------------------------------
        # 7. Persist validation
        # --------------------------------------------------

        validation = Validation(
            exploit_id=exploit.id,
            twin_id=twin.id,
            status=status,
            validation_score=score,
            analysis=analysis,
            evidence=execution.evidence,
        )

        db.add(validation)
        db.commit()
        db.refresh(validation)

        return OrchestrationResult(
            validation=validation,
            execution=execution,
            readiness=readiness,
        )