from typing import Any


class RevalidationEngine:
    """Custom remediation verification engine."""

    def verify(self, validation_score: float, evidence: dict[str, Any] | None = None) -> tuple[str, float, dict[str, Any]]:
        """Verify whether remediation reduced exploit validation confidence."""

        evidence = evidence or {}
        residual = max(0.0, min(1.0, validation_score))
        verification_score = 1.0 - residual
        status = "verified" if verification_score >= 0.75 else "partial" if verification_score >= 0.45 else "failed"
        return status, verification_score, {"residual_validation_score": residual, **evidence}
