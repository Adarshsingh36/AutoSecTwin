"""
Gathers every real row the closed-loop technical report needs for a given
remediation, then hands them to ReportGenerator.generate_closed_loop_report().

Kept separate from ReportGenerator itself so that class stays a pure
formatter with no DB dependency (easy to unit test with plain objects) --
this module is the only place that queries the database for report data.
"""

from __future__ import annotations

import json
from typing import Any, Optional

from sqlalchemy.orm import Session
from core.config import settings
from database.models.approval import Approval
from database.models.exploit import Exploit
from database.models.recommendation import Recommendation
from database.models.remediation import Remediation
from database.models.report import Report
from database.models.twin import Twin
from database.models.validation import Validation
from database.models.vulnerability import Vulnerability
from services.reporting.report_generator import ReportGenerator


def build_closed_loop_report(db: Session, remediation_id: int) -> str:
    """Build the full closed-loop technical report JSON body for a
    remediation. Raises ValueError if the remediation doesn't exist --
    every other piece of data is optional and reported as missing, not
    fabricated, if it can't be found.
    """

    remediation = db.query(Remediation).filter(Remediation.id == remediation_id).first()
    if remediation is None:
        raise ValueError(f"Remediation {remediation_id} not found.")

    vulnerability = (
        db.query(Vulnerability).filter(Vulnerability.id == remediation.vulnerability_id).first()
    )

    recommendation: Optional[Recommendation] = None
    if remediation.recommendation_id is not None:
        recommendation = (
            db.query(Recommendation)
            .filter(Recommendation.id == remediation.recommendation_id)
            .first()
        )

    approval = (
        db.query(Approval).filter(Approval.remediation_id == remediation.id).first()
    )

    evidence = remediation.evidence or {}

    # The "before" twin is the one remediation.evidence recorded as
    # old_twin_id (PatchExecutor's execution record) -- the current
    # target_twin_id is the "after" (fixed) twin once execution succeeded.
    old_twin_id = evidence.get("old_twin_id")
    new_twin = (
        db.query(Twin).filter(Twin.id == remediation.target_twin_id).first()
        if remediation.target_twin_id
        else None
    )
    old_twin = (
        db.query(Twin).filter(Twin.id == old_twin_id).first() if old_twin_id else None
    )

    initial_validation = (
        db.query(Validation)
        .filter(Validation.vulnerability_id == remediation.vulnerability_id, Validation.phase == "initial")
        .order_by(Validation.created_at.desc())
        .first()
    )

    revalidation = (
        db.query(Validation)
        .filter(Validation.vulnerability_id == remediation.vulnerability_id, Validation.phase == "revalidation")
        .order_by(Validation.created_at.desc())
        .first()
    )

    exploit: Optional[Exploit] = None
    if initial_validation is not None and initial_validation.exploit_id is not None:
        exploit = db.query(Exploit).filter(Exploit.id == initial_validation.exploit_id).first()

    audit_trail = _build_audit_trail(
        vulnerability, initial_validation, recommendation, approval, remediation, revalidation
    )

    final_status = remediation.status

    title = (
        f"AutoSecTwin Closed-Loop Remediation Report -- "
        f"{getattr(vulnerability, 'cve_id', 'Unknown CVE')} "
        f"(Remediation #{remediation.id})"
    )

    return ReportGenerator().generate_closed_loop_report(
        title=title,
        vulnerability=vulnerability,
        twin=new_twin or old_twin,
        old_twin=old_twin,
        new_twin=new_twin,
        exploit=exploit,
        initial_validation=initial_validation,
        recommendation=recommendation,
        approval=approval,
        remediation=remediation,
        revalidation=revalidation,
        revalidation_comparison=evidence.get("revalidation_comparison"),
        before_after=evidence.get("before_after"),
        final_status=final_status,
        audit_trail=audit_trail,
        exploitability_probability=getattr(
            vulnerability, "exploitability_probability", None
        ),
        mock_mode=settings.MOCK_MODE,
    )


def persist_closed_loop_report(db: Session, remediation_id: int) -> Report:
    """Create or refresh the final report for a remediation workflow."""

    remediation = db.get(Remediation, remediation_id)
    if remediation is None:
        raise ValueError(f"Remediation {remediation_id} not found.")

    content = build_closed_loop_report(db, remediation_id)
    body = json.loads(content)
    metadata = {"remediation_id": remediation_id}
    reports = (
        db.query(Report)
        .filter(
            Report.vulnerability_id == remediation.vulnerability_id,
            Report.report_type == "closed_loop",
        )
        .order_by(Report.id.desc())
        .all()
    )
    report = next(
        (
            candidate
            for candidate in reports
            if (candidate.metadata_json or {}).get("remediation_id") == remediation_id
        ),
        None,
    )
    if report is None:
        report = Report(
            vulnerability_id=remediation.vulnerability_id,
            report_type="closed_loop",
            title=body.get("title", f"Closed-Loop Report: Remediation {remediation_id}"),
            content=content,
            format="json",
            metadata_json=metadata,
        )
        db.add(report)
    else:
        report.title = body.get("title", report.title)
        report.content = content
        report.metadata_json = metadata

    db.commit()
    db.refresh(report)
    return report

def _is_simulated_evidence(evidence: Any) -> bool:
    """Detect simulation markers in current and legacy evidence formats."""
    if not isinstance(evidence, dict):
        return False

    if evidence.get("simulated") is True:
        return True

    raw_result = evidence.get("raw_result")
    if isinstance(raw_result, dict) and raw_result.get("simulated") is True:
        return True

    return False


def _any_simulated(*validations) -> bool:
    """Return True if any supplied validation contains simulation markers."""
    for validation in validations:
        evidence = getattr(validation, "evidence", None) or {}
        if _is_simulated_evidence(evidence):
            return True

    return False

def _build_audit_trail(
    vulnerability: Optional[Vulnerability],
    initial_validation: Optional[Validation],
    recommendation: Optional[Recommendation],
    approval: Optional[Approval],
    remediation: Remediation,
    revalidation: Optional[Validation],
) -> list[dict[str, Any]]:
    """Synthesize a chronological timeline from real, persisted
    timestamps across the chain -- never invented events, only what's
    actually on these rows.
    """

    events: list[dict[str, Any]] = []

    def _add(event: str, timestamp: Any, detail: Optional[str] = None) -> None:
        if timestamp is None:
            return
        events.append({"event": event, "timestamp": timestamp, "detail": detail})

    if vulnerability is not None:
        _add("Vulnerability recorded", getattr(vulnerability, "created_at", None), vulnerability.cve_id)
    if initial_validation is not None:
        _add(
            "Initial exploit validation",
            initial_validation.created_at,
            f"status={initial_validation.status} score={initial_validation.validation_score}",
        )
    if recommendation is not None:
        _add("Recommendation generated", recommendation.created_at, recommendation.title)
    if approval is not None:
        _add("Approval requested", approval.created_at, f"requested_by={approval.requested_by}")
        _add(
            "Approval decided",
            approval.decided_at,
            f"status={approval.status} decided_by={approval.decided_by}",
        )
    _add("Remediation created", remediation.created_at, remediation.action)
    _add("Remediation execution started", remediation.execution_started_at)
    _add(
        "Remediation execution completed",
        remediation.execution_completed_at,
        f"status={remediation.status} target_modified={remediation.target_modified}",
    )
    if revalidation is not None:
        _add(
            "Revalidation executed",
            revalidation.created_at,
            f"status={revalidation.status} score={revalidation.validation_score}",
        )
    _add("Remediation verified", remediation.verified_at)

    events.sort(key=lambda e: str(e["timestamp"]))
    return events
