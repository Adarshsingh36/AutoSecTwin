"""
Tests for services/remediation/comparison.py -- pure mapping from
persisted Validation rows into the structured before/after shape.
"""

from types import SimpleNamespace

from services.remediation.comparison import build_before_after_comparison


def _validation(id_, twin_id, status, score, execution_outcome, detected_version=None):
    return SimpleNamespace(
        id=id_,
        twin_id=twin_id,
        status=status,
        validation_score=score,
        evidence={"execution_outcome": execution_outcome, "detected_version": detected_version},
    )


def test_resolved_case_matches_spec_shape():
    before = _validation(21, twin_id=1, status="validated", score=0.75, execution_outcome="session_established", detected_version="5.17.3")
    after = _validation(45, twin_id=2, status="failed", score=0.0, execution_outcome="confirmed_no_session", detected_version="5.17.6")

    comparison = build_before_after_comparison(before, after, outcome="resolved")

    assert comparison == {
        "before": {
            "twin_id": 1,
            "version": "5.17.3",
            "validation_id": 21,
            "status": "validated",
            "validation_score": 0.75,
            "exploit_result": "successful",
        },
        "after": {
            "twin_id": 2,
            "version": "5.17.6",
            "validation_id": 45,
            "status": "not_exploitable",
            "validation_score": 0.0,
            "exploit_result": "not_exploitable",
        },
        "resolved": True,
    }


def test_still_vulnerable_case_is_not_resolved():
    before = _validation(1, 1, "validated", 0.8, "session_established")
    after = _validation(2, 2, "validated", 0.75, "session_established")

    comparison = build_before_after_comparison(before, after, outcome="still_vulnerable")

    assert comparison["resolved"] is False
    assert comparison["after"]["status"] == "validated"
    assert comparison["after"]["exploit_result"] == "successful"


def test_inconclusive_outcome_is_never_resolved_even_with_low_score():
    """The `outcome` parameter is the sole source of truth for `resolved`
    -- a low score from a timeout must not flip this to True."""
    before = _validation(1, 1, "validated", 0.8, "session_established")
    after = _validation(2, 2, "inconclusive", 0.0, "timeout_inconclusive")

    comparison = build_before_after_comparison(before, after, outcome="inconclusive")

    assert comparison["resolved"] is False
    assert comparison["after"]["exploit_result"] == "inconclusive"


def test_missing_evidence_does_not_crash():
    before = SimpleNamespace(id=1, twin_id=1, status="validated", validation_score=0.8, evidence=None)
    after = SimpleNamespace(id=2, twin_id=2, status="failed", validation_score=0.0, evidence=None)

    comparison = build_before_after_comparison(before, after, outcome="resolved")

    assert comparison["before"]["version"] is None
    assert comparison["after"]["exploit_result"] == "unknown"
