from typing import Any

# execution_outcome values (see services/orchestration/exploit_executor.py)
# that mean "we genuinely don't know" -- these must never be scored as a
# definitive negative. A timeout, RPC failure, or readiness block is not
# evidence that a target isn't exploitable; it's an absence of evidence or
# a precondition failure that must be reviewed, not treated as a confirmed
# negative.
_INCONCLUSIVE_OUTCOMES = {"timeout_inconclusive", "rpc_error", "readiness_blocked"}

_INCONCLUSIVE_PATTERNS = (
    "timeout",
    "connection refused",
    "no route to host",
    "rpc connection refused",
    "network unreachable",
    "readiness",
)


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
        stage = str(evidence.get("stage", "") or "").lower()
        execution_outcome = evidence.get("execution_outcome")

        score = 0.0
        if exit_code == 0:
            score += 0.25
        score += min(0.60, 0.20 * marker_hits)
        if "failed" not in stderr and "timeout" not in stderr:
            score += 0.15

        score = max(0.0, min(1.0, score))

        if (
            execution_outcome in _INCONCLUSIVE_OUTCOMES
            or stage == "readiness"
            or any(pattern in stderr for pattern in _INCONCLUSIVE_PATTERNS)
            or any(pattern in str(execution_outcome or "").lower() for pattern in _INCONCLUSIVE_PATTERNS)
        ):
            status = "inconclusive"
            score = 0.0
        else:
            status = "validated" if score >= 0.70 else "inconclusive" if score >= 0.35 else "failed"

        analysis = f"Validation status={status}; marker_hits={marker_hits}; score={score:.3f}"
        if execution_outcome:
            analysis += f"; execution_outcome={execution_outcome}"
        if stage:
            analysis += f"; stage={stage}"
        return status, score, analysis
