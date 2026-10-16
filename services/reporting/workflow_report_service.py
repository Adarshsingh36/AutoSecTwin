from __future__ import annotations

import json
from typing import Any

from sqlalchemy.orm import Session

from database.models.approval import Approval
from database.models.exploit import Exploit
from database.models.recommendation import Recommendation
from database.models.report import Report
from database.models.twin import Twin
from database.models.validation import Validation
from database.models.vulnerability import Vulnerability
from services.learning.event_recorder import record_learning_event
from services.reporting.report_generator import ReportGenerator


def create_validation_report(
    db: Session,
    vulnerability: Vulnerability | None,
    validation: Validation,
    exploit: Exploit | None = None,
    twin: Twin | None = None,
    recommendation: Recommendation | None = None,
    approval: Approval | None = None,
    evidence_source: str = "user_submitted",
) -> Report:
    """Persist a report from the actual validation and related records."""

    evidence = validation.evidence or {}
    plain_language = build_plain_language_assessment(validation, evidence)
    payload: dict[str, Any] = {
        "plain_language": plain_language,
        "evidence_source": evidence_source,
        "evidence_simulated": _is_simulated(evidence),
        "vulnerability": _vulnerability_data(vulnerability),
        "validation": {
            "id": validation.id,
            "phase": validation.phase,
            "status": validation.status,
            "score": validation.validation_score,
            "analysis": validation.analysis,
            "evidence": evidence,
        },
        "exploit": (
            {
                "id": exploit.id,
                "source": exploit.source,
                "module_name": exploit.module_name,
                "title": exploit.title,
            }
            if exploit is not None
            else None
        ),
        "target_twin": (
            {
                "id": twin.id,
                "name": twin.name,
                "provider": twin.provider,
                "status": twin.status,
                "endpoint": twin.endpoint,
            }
            if twin is not None
            else None
        ),
        "recommendation": (
            {
                "id": recommendation.id,
                "title": recommendation.title,
                "content": recommendation.content,
                "provider": recommendation.provider,
            }
            if recommendation is not None
            else None
        ),
        "human_approval": (
            {
                "id": approval.id,
                "status": approval.status,
                "requested_action": approval.requested_action,
                "context": approval.context,
            }
            if approval is not None
            else None
        ),
    }

    cve_id = vulnerability.cve_id if vulnerability is not None else "Unknown finding"
    title = f"AutoSecTwin Validation Report - {cve_id}"
    report = Report(
        vulnerability_id=vulnerability.id if vulnerability is not None else None,
        report_type="technical",
        title=title,
        content=ReportGenerator().generate("technical", title, payload),
        format="json",
        metadata_json={
            "evidence_source": evidence_source,
            "validation_id": validation.id,
            "recommendation_id": recommendation.id if recommendation else None,
            "approval_id": approval.id if approval else None,
        },
    )
    db.add(report)
    db.commit()
    db.refresh(report)
    record_learning_event(
        db,
        event_type="validation_feedback",
        source=evidence_source,
        label=validation.status,
        payload={
            "vulnerability_id": validation.vulnerability_id,
            "validation_id": validation.id,
            "report_id": report.id,
            "validation_score": validation.validation_score,
            "simulated": plain_language["simulated_evidence"],
        },
        notes="Recorded validation outcome for future calibration; no model was retrained.",
    )
    return report


def create_approval_decision_report(db: Session, approval: Approval) -> Report:
    """Record an approval decision, including a rejection that leaves the
    vulnerability unresolved and does not create a remediation.
    """

    vulnerability = db.get(Vulnerability, approval.vulnerability_id)
    recommendation = (
        db.get(Recommendation, approval.recommendation_id)
        if approval.recommendation_id is not None
        else None
    )
    rejected = approval.status == "rejected"
    if rejected:
        outcome = "The proposed action was declined. The vulnerability remains unresolved."
    elif approval.requested_action == "recommend_only":
        outcome = (
            "The recommendation was accepted for reporting. No patch was deployed; "
            "a separate Twin-specific approval is required before any change is applied."
        )
    else:
        outcome = "Remediation was approved. Execution status is tracked separately."
    title = (
        f"AutoSecTwin Approval Decision - "
        f"{vulnerability.cve_id if vulnerability else approval.vulnerability_id}"
    )
    payload = {
        "vulnerability": _vulnerability_data(vulnerability),
        "recommendation": (
            {
                "id": recommendation.id,
                "title": recommendation.title,
                "content": recommendation.content,
            }
            if recommendation is not None
            else None
        ),
        "review_package": (approval.context or {}).get("review_package"),
        "human_decision": {
            "approval_id": approval.id,
            "status": approval.status,
            "requested_action": approval.requested_action,
            "requested_by": approval.requested_by,
            "decided_by": approval.decided_by,
            "decision_reason": approval.decision_reason,
            "decided_at": approval.decided_at,
        },
        "outcome": outcome,
    }
    report = Report(
        vulnerability_id=approval.vulnerability_id,
        report_type="technical",
        title=title,
        content=ReportGenerator().generate("technical", title, payload),
        format="json",
        metadata_json={
            "workflow_stage": "approval_decision",
            "approval_id": approval.id,
        },
    )
    db.add(report)
    db.commit()
    db.refresh(report)
    record_learning_event(
        db,
        event_type="human_approval_feedback",
        source="approval_review",
        label=approval.status,
        payload={
            "approval_id": approval.id,
            "vulnerability_id": approval.vulnerability_id,
            "recommendation_id": approval.recommendation_id,
            "remediation_id": approval.remediation_id,
            "decision_reason": approval.decision_reason,
        },
        notes="Recorded human review feedback for future calibration; no model was retrained.",
    )
    return report


def revise_recommendation_review(
    db: Session,
    approval: Approval,
    human_response: str,
) -> Report | None:
    """Carry a requested text amendment into a new recommendation/report revision.

    This only edits recommendation text for recommendation-only reviews. A
    deployable approval keeps its target and version immutable and must be
    re-proposed by an operator if the reviewer requests a change.
    """

    context = dict(approval.context or {})
    history = list(context.get("revision_history") or [])
    report: Report | None = None

    if approval.requested_action == "recommend_only":
        review_package = dict(context.get("review_package") or {})
        recommendation_data = dict(review_package.get("recommendation") or {})
        recommendation = (
            db.get(Recommendation, approval.recommendation_id)
            if approval.recommendation_id is not None
            else None
        )
        previous_content = (
            recommendation.content
            if recommendation is not None
            else str(recommendation_data.get("content") or "")
        )
        updated_content = (
            f"{previous_content}\n\nReviewer-requested amendment (not yet approved): "
            f"{human_response}"
        ).strip()
        if recommendation is not None:
            recommendation.content = updated_content
        recommendation_data["content"] = updated_content
        review_package["recommendation"] = recommendation_data

        previous_report_id = context.get("report_id")
        previous_report = (
            db.get(Report, previous_report_id) if previous_report_id is not None else None
        )
        if previous_report is not None:
            report_body = json.loads(previous_report.content)
            report_findings = report_body.setdefault("findings", {})
            report_findings["recommendation"] = recommendation_data
            report_findings["reviewer_requested_changes"] = human_response
            report_body["summary"] = (
                f"{report_body.get('summary', '')} A reviewer-requested recommendation amendment is pending approval."
            ).strip()
            report = Report(
                vulnerability_id=previous_report.vulnerability_id,
                report_type=previous_report.report_type,
                title=f"{previous_report.title} - Review Revision {len(history) + 1}",
                content=json.dumps(report_body, indent=2, default=str),
                format=previous_report.format,
                metadata_json={
                    "workflow_stage": "recommendation_revision",
                    "approval_id": approval.id,
                    "parent_report_id": previous_report.id,
                    "review_revision": len(history) + 1,
                },
            )
            db.add(report)
            db.flush()
            context["report_id"] = report.id
            review_package["report_id"] = report.id
        context["review_package"] = review_package

    history.append(
        {
            "response": human_response,
            "interpretation": "revision_requested",
            "report_id": report.id if report else context.get("report_id"),
        }
    )
    context["revision_history"] = history
    context["human_response"] = human_response
    context["response_interpretation"] = "revision_requested"
    if approval.requested_action != "recommend_only":
        context["reproposal_required"] = True
    approval.context = context
    db.commit()
    if report is not None:
        db.refresh(report)
    db.refresh(approval)
    return report


def _vulnerability_data(vulnerability: Vulnerability | None) -> dict[str, Any] | None:
    if vulnerability is None:
        return None
    return {
        "id": vulnerability.id,
        "cve_id": vulnerability.cve_id,
        "title": vulnerability.title,
        "description": vulnerability.description,
        "severity": vulnerability.severity,
        "cvss_score": vulnerability.cvss_score,
        "epss_score": vulnerability.epss_score,
        "exploitability_probability": vulnerability.exploitability_probability,
        "threat_intelligence_score": vulnerability.threat_intelligence_score,
    }


def _is_simulated(evidence: dict[str, Any]) -> bool:
    if evidence.get("simulated") is True:
        return True
    raw_result = evidence.get("raw_result")
    return isinstance(raw_result, dict) and raw_result.get("simulated") is True


def build_plain_language_assessment(
    validation: Validation,
    evidence: dict[str, Any],
) -> dict[str, Any]:
    """Explain submitted evidence without overstating what it proves."""

    findings = evidence.get("findings")
    if not isinstance(findings, list):
        findings = []

    explanations: list[dict[str, str]] = []
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        title = str(finding.get("title") or finding.get("id") or "Submitted finding")
        status = str(finding.get("status") or "requires_review")
        status_key = status.lower()
        impact = finding.get("impact")
        if finding.get("http_status") == 403 or "blocked" in status_key:
            explanation = (
                "The tested request was blocked, so direct access was not demonstrated. "
                "A listed filename alone does not prove that its contents were exposed."
            )
        elif "informational" in status_key:
            explanation = (
                "This is contextual information, not proof that access controls were bypassed."
            )
        elif any(term in status_key for term in ("confirmed", "observed", "exposure")):
            explanation = (
                "The described behavior was observed. This alone does not establish that an "
                "attacker used it to access an account or take control of the application."
            )
        else:
            explanation = (
                "This item still needs testing before its security impact can be confirmed."
            )
        explanations.append(
            {
                "id": str(finding.get("id") or ""),
                "title": title,
                "status": status,
                "explanation": str(impact or explanation),
            }
        )

    actions = evidence.get("recommended_remediations")
    if not isinstance(actions, list):
        actions = []
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            title = str(finding.get("title") or "").lower()
            status = str(finding.get("status") or "").lower()
            if "ftp" in title or "directory listing" in title:
                actions.append(
                    "Disable public directory listing and remove files not intended for public access."
                )
            elif "kdbx" in title or "password database" in title:
                actions.append(
                    "Review the database safely; if it contains credentials, rotate them and restrict or remove public access."
                )
            elif "cors" in title:
                actions.append(
                    "Restrict cross-origin access to trusted sites where needed, then retest sensitive endpoints."
                )
            elif "backup" in title or "backup" in status:
                actions.append(
                    "Keep direct access blocked and remove backup files from the public web directory."
                )
            elif "robots" in title:
                actions.append(
                    "Do not treat robots.txt as access control; no security fix is established by this observation alone."
                )

    actions = list(dict.fromkeys(str(action) for action in actions if action))
    simulated = _is_simulated(evidence)
    demonstrated = evidence.get("exploitation_demonstrated") is True
    if demonstrated:
        conclusion = "The submitted evidence says exploitation was demonstrated; review the evidence details before acting."
    elif explanations:
        conclusion = (
            "The assessment recorded the observations listed below, but it does not show a successful application exploit, "
            "account compromise, or remediation. Items marked provisional or informational need further verification."
        )
    elif validation.status == "validated":
        conclusion = "The controlled validation recorded evidence consistent with successful exploitation."
    elif validation.status == "failed":
        conclusion = "The test did not confirm exploitation. This does not prove the application is free of vulnerabilities."
    else:
        conclusion = "The available evidence is not sufficient to determine whether exploitation succeeded."

    if simulated:
        conclusion += " Some or all execution evidence was simulated and is not proof of real-world impact."

    return {
        "summary": conclusion,
        "findings": explanations,
        "recommended_next_steps": actions,
        "exploitation_demonstrated": demonstrated,
        "simulated_evidence": simulated,
    }