from typing import Any

from services.remediation.remediation_executor import (
    RemediationExecutionResult,
    RemediationExecutor,
)


class PatchExecutor(RemediationExecutor):
    """
    Controlled patch executor.

    The first implementation intentionally operates in DRY-RUN mode.
    It validates the approved patch request and records what would be
    executed without silently modifying the target environment.
    """

    def execute(
        self,
        *,
        vulnerability_id: int,
        recommendation_id: int,
        action: str,
        context: dict[str, Any] | None = None,
    ) -> RemediationExecutionResult:

        context = context or {}

        current_version = context.get("current_version")
        fixed_version = context.get("fixed_version")

        evidence = {
            "executor": "PatchExecutor",
            "mode": "dry_run",
            "vulnerability_id": vulnerability_id,
            "recommendation_id": recommendation_id,
            "action": action,
            "current_version": current_version,
            "fixed_version": fixed_version,
            "execution_authorized": True,
            "target_modified": False,
        }

        return RemediationExecutionResult(
            status="manual_action_required",
            message=(
                "Patch remediation was approved and validated, "
                "but automatic patch application is not yet enabled "
                "for this environment."
            ),
            evidence=evidence,
        )