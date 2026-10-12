"""
Structured before/after comparison for a remediation, built entirely from
persisted Validation rows -- never from values supplied by a caller. See
services/revalidation/revalidation_engine.py for how `outcome` is derived
(and why a timeout/RPC error there can never become "resolved" here).
"""

from __future__ import annotations

from typing import Any, Optional

from database.models.validation import Validation

# Maps ValidationEngine's internal status vocabulary to the more
# report-friendly terms used in this comparison -- "failed" (a confirmed
# negative) reads as "not_exploitable" here, which is clearer to a human
# reviewer than "failed" (which could be misread as "the test itself
# broke"). The underlying Validation.status column is untouched.
_STATUS_DISPLAY = {
    "failed": "not_exploitable",
    "validated": "validated",
    "inconclusive": "inconclusive",
}

_OUTCOME_DISPLAY = {
    "session_established": "successful",
    "confirmed_no_session": "not_exploitable",
    "timeout_inconclusive": "inconclusive",
    "rpc_error": "inconclusive",
    "readiness_blocked": "inconclusive",
}


def _side(validation: Validation) -> dict[str, Any]:
    evidence = validation.evidence or {}
    execution_outcome = evidence.get("execution_outcome")

    return {
        "twin_id": validation.twin_id,
        "version": evidence.get("detected_version"),
        "validation_id": validation.id,
        "status": _STATUS_DISPLAY.get(validation.status, validation.status),
        "validation_score": validation.validation_score,
        "exploit_result": _OUTCOME_DISPLAY.get(execution_outcome, "unknown"),
    }


def build_before_after_comparison(
    initial_validation: Validation,
    revalidation: Validation,
    outcome: str,
) -> dict[str, Any]:
    """`outcome` is RevalidationSummary.result ("resolved" | "still_vulnerable"
    | "inconclusive") -- the single source of truth for `resolved`, so this
    function never recomputes that decision from scores itself.
    """

    return {
        "before": _side(initial_validation),
        "after": _side(revalidation),
        "resolved": outcome == "resolved",
    }
