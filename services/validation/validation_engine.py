from typing import Any


class ValidationEngine:
    """Custom exploit validation analysis for twin evidence."""

    SUCCESS_MARKERS = ("shell_opened", "proof_obtained", "version_confirmed", "callback_received")

    def analyze(self, evidence: dict[str, Any] | None) -> tuple[str, float, str]:
        """Return status, validation score V(e), and human-readable analysis."""

        evidence = evidence or {}
        markers = evidence.get("markers", [])
        if isinstance(markers, str):
            markers = [markers]
        marker_hits = sum(1 for marker in markers if marker in self.SUCCESS_MARKERS)
        exit_code = evidence.get("exit_code")
        stderr = str(evidence.get("stderr", "") or "").lower()

        score = 0.0
        if exit_code == 0:
            score += 0.25
        score += min(0.60, 0.20 * marker_hits)
        if "failed" not in stderr and "timeout" not in stderr:
            score += 0.15

        score = max(0.0, min(1.0, score))
        status = "validated" if score >= 0.70 else "inconclusive" if score >= 0.35 else "failed"
        analysis = f"Validation status={status}; marker_hits={marker_hits}; score={score:.3f}"
        return status, score, analysis
