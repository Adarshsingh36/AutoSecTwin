from dataclasses import dataclass
from typing import Any


@dataclass
class RemediationExecutionResult:
    status: str
    message: str
    evidence: dict[str, Any]


class RemediationExecutor:
    """
    Base abstraction for controlled remediation execution.

    Concrete remediation handlers must explicitly implement execute().
    """

    def execute(
        self,
        *,
        vulnerability_id: int,
        recommendation_id: int | None,
        action: str,
        context: dict[str, Any] | None = None,
    ) -> RemediationExecutionResult:
        raise NotImplementedError(
            "Concrete remediation handlers must implement execute()."
        )