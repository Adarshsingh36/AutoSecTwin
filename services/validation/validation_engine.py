
from typing import Any


# Outcomes that do not establish whether exploitation succeeded.
_INCONCLUSIVE_OUTCOMES = {
    "timeout_inconclusive",
    "rpc_error",
    "readiness_blocked",
}

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

    SUCCESS_MARKERS = (
        "shell_opened",
        "proof_obtained",
        "version_confirmed",
        "callback_received",
    )

    def analyze(
        self, evidence: dict[str, Any] | None
    ) -> tuple[str, float, str]:
        """Classify validation using execution outcomes and evidence.

        Explicit inconclusive outcomes must never be treated as definitive
        failures. Legacy evidence without execution_outcome retains
        marker-based scoring.
        """
        evidence = evidence or {}

        execution_outcome = str(
            evidence.get("execution_outcome") or ""
        ).strip().lower()

        stderr = str(evidence.get("stderr") or "").lower()
        stage = str(evidence.get("stage") or "").lower()

        # A readiness failure or transport/RPC error is not proof
        # that the target is not exploitable.
        if execution_outcome in _INCONCLUSIVE_OUTCOMES:
            return (
                "inconclusive",
                0.0,
                f"Validation inconclusive: execution_outcome={execution_outcome}.",
            )

        if stage == "readiness" and evidence.get("ready") is False:
            return (
                "inconclusive",
                0.0,
                "Validation inconclusive: readiness check blocked execution.",
            )

        if any(pattern in stderr for pattern in _INCONCLUSIVE_PATTERNS):
            return (
                "inconclusive",
                0.0,
                f"Validation inconclusive: execution error detected "
                f"(stderr={stderr!r}).",
            )

        markers = evidence.get("markers", [])
        if isinstance(markers, str):
            markers = [markers]
        if not isinstance(markers, (list, tuple, set)):
            markers = []

        success_markers = set(self.SUCCESS_MARKERS)
        marker_hits = sum(
            1
            for marker in markers
            if isinstance(marker, str) and marker in success_markers
        )

        session_id = evidence.get("session_id")

        if execution_outcome == "session_established":
            # Require corroborating evidence, not merely an outcome label.
            if session_id is None and marker_hits == 0:
                return (
                    "inconclusive",
                    0.0,
                    "Validation inconclusive: session_established was "
                    "reported without corroborating evidence.",
                )

            score = min(1.0, 0.70 + min(0.30, 0.10 * marker_hits))
            return (
                "validated",
                score,
                f"Validation status=validated; marker_hits={marker_hits}; "
                f"execution_outcome={execution_outcome}.",
            )

        if execution_outcome == "confirmed_no_session":
            return (
                "failed",
                0.0,
                "Validation completed without a session; "
                "execution_outcome=confirmed_no_session.",
            )

        # Backward compatibility: older evidence has no execution_outcome.
        # Preserve marker-based scoring for successful legacy evidence.
        if not execution_outcome:
            if marker_hits:
                score = min(1.0, marker_hits / 2.0)
                return (
                    "validated",
                    score,
                    f"Legacy validation evidence; marker_hits={marker_hits}.",
                )

            return (
                "inconclusive",
                0.0,
                "Legacy validation evidence contains no success markers "
                "or definitive execution outcome.",
            )

        # Unknown explicit outcomes must not be converted into a failure.
        return (
            "inconclusive",
            0.0,
            f"Validation inconclusive: unrecognized execution outcome "
            f"({execution_outcome}).",
        )
