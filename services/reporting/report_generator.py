import io
import json
from typing import Any, Optional

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    ListFlowable,
    ListItem,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from services.reporting.cve_knowledge import (
    VALIDATION_SCORE_EXPLANATION,
    get_cve_technical_explanation,
)


class ReportGenerator:
    """Generates executive, technical, trust, legacy, remediation, and validation reports."""

    SUPPORTED_TYPES = {
        "executive",
        "technical",
        "trust",
        "legacy",
        "remediation",
        "validation",
        "closed_loop",
    }

    def generate(self, report_type: str, title: str, payload: dict[str, Any]) -> str:
        """Generate a JSON report body for the requested report type."""

        normalized_type = report_type.lower().replace("_report", "").replace(" report", "")
        if normalized_type not in self.SUPPORTED_TYPES:
            normalized_type = "technical"
        body = {
            "report_type": normalized_type,
            "title": title,
            "summary": self._summary(normalized_type, payload),
            "findings": payload,
        }
        return json.dumps(body, indent=2, default=str)

    def generate_closed_loop_report(
        self,
        title: str,
        vulnerability: Any,
        twin: Any,
        exploit: Any | None,
        initial_validation: Any | None,
        remediation: Any | None,
        revalidation: Any | None,
        revalidation_comparison: str | None,
        final_status: str,
        audit_trail: list[dict[str, Any]],
        exploitability_probability: float | None = None,
        mock_mode: bool = False,
        old_twin: Any | None = None,
        new_twin: Any | None = None,
        recommendation: Any | None = None,
        approval: Any | None = None,
        before_after: dict[str, Any] | None = None,
    ) -> str:
        """Build the full technical closed-loop report.

        Every section is populated from database rows passed in by the
        caller (services/reporting/closed_loop_report_service.py), never
        from ad hoc runtime variables -- a field this function can't find
        on the objects it's given is reported as missing/not-available,
        never invented. `twin` is kept for backward compatibility with the
        original single-twin signature; prefer passing old_twin/new_twin
        explicitly when both are known (the normal case post-remediation).
        """

        cve_id = getattr(vulnerability, "cve_id", None)
        cve_explanation = get_cve_technical_explanation(cve_id)

        exploit_evidence = getattr(initial_validation, "evidence", None) or {}
        revalidation_evidence = getattr(revalidation, "evidence", None) or {}

        body: dict[str, Any] = {
            "report_type": "closed_loop",
            "title": title,
            "generated_in_mock_mode": mock_mode,
            "1_executive_summary": self._executive_summary(
                vulnerability, final_status, exploitability_probability, initial_validation, remediation
            ),
            "2_system_under_test": self._system_under_test(old_twin or twin, new_twin),
            "3_vulnerability_technical_analysis": self._vulnerability_technical_analysis(
                vulnerability, cve_explanation
            ),
            "4_detection_pipeline": self._detection_pipeline(vulnerability, exploitability_probability, exploit),
            "5_exploit_technical_execution": self._exploit_technical_execution(exploit, exploit_evidence),
            "6_evidence_collected": self._evidence_collected(exploit_evidence),
            "7_validation_engine": self._validation_engine_section(initial_validation),
            "8_recommendation": self._recommendation_section(recommendation, old_twin or twin, new_twin, approval),
            "9_human_approval": self._human_approval_section(approval),
            "10_remediation_execution": self._remediation_execution_section(remediation, old_twin, new_twin),
            "11_revalidation": self._revalidation_section(exploit, new_twin, revalidation, revalidation_evidence, revalidation_comparison),
            "12_before_vs_after": before_after or {"note": "No before/after comparison is available yet for this remediation."},
            "13_final_security_state": self._final_security_state(remediation, before_after),
            "14_limitations": self._limitations(approval, cve_explanation, mock_mode),
            "15_technical_appendix": self._technical_appendix(
                vulnerability, exploit, initial_validation, recommendation, approval, remediation, revalidation, old_twin, new_twin, audit_trail
            ),
        }
        return json.dumps(body, indent=2, default=str)

    # -- section builders ---------------------------------------------------

    @staticmethod
    def _executive_summary(vulnerability, final_status, exploitability_probability, initial_validation, remediation) -> dict[str, Any]:
        return {
            "asset": getattr(getattr(vulnerability, "asset", None), "name", None),
            "vulnerability": getattr(vulnerability, "cve_id", None),
            "risk_severity": getattr(vulnerability, "severity", None),
            "cvss_score": getattr(vulnerability, "cvss_score", None),
            "exploitability_probability": exploitability_probability,
            "initial_validation_result": getattr(initial_validation, "status", None),
            "remediation_result": getattr(remediation, "status", None),
            "final_status": final_status,
            "summary": (
                f"{getattr(vulnerability, 'cve_id', 'This vulnerability')} was validated against an "
                f"isolated Digital Twin, {'remediated and revalidated' if final_status == 'verified' else 'processed through the remediation workflow'}. "
                f"Final status: {final_status}."
            ),
        }

    @staticmethod
    def _twin_snapshot(twin) -> Optional[dict[str, Any]]:
        if twin is None:
            return None
        return {
            "twin_id": getattr(twin, "id", None),
            "provider": getattr(twin, "provider", None),
            "environment": getattr(twin, "environment", None),
            "docker_image": getattr(twin, "twin_image", None),
            "network": getattr(twin, "network", None),
            "ip_address": getattr(twin, "ip_address", None),
            "endpoint": getattr(twin, "endpoint", None),
            "health": getattr(twin, "health", None),
            "status": getattr(twin, "status", None),
        }

    def _system_under_test(self, old_twin, new_twin) -> dict[str, Any]:
        return {
            "before_remediation": self._twin_snapshot(old_twin),
            "after_remediation": self._twin_snapshot(new_twin),
        }

    @staticmethod
    def _vulnerability_technical_analysis(vulnerability, cve_explanation: dict[str, Any]) -> dict[str, Any]:
        return {
            "cve_id": getattr(vulnerability, "cve_id", None),
            "cvss_score": getattr(vulnerability, "cvss_score", None),
            "epss_score": getattr(vulnerability, "epss_score", None),
            "kev_listed": getattr(vulnerability, "kev_listed", None),
            "description": getattr(vulnerability, "description", None),
            "technical_explanation_available": cve_explanation.get("available"),
            "affected_component": cve_explanation.get("affected_component"),
            "affected_versions": cve_explanation.get("affected_versions"),
            "affected_protocol_port": cve_explanation.get("protocol_port"),
            "attack_chain": cve_explanation.get("attack_chain"),
            "root_cause": cve_explanation.get("root_cause"),
            "source": cve_explanation.get("source") or cve_explanation.get("note"),
        }

    @staticmethod
    def _detection_pipeline(vulnerability, exploitability_probability, exploit) -> dict[str, Any]:
        return {
            "vulnerability_record_id": getattr(vulnerability, "id", None),
            "threat_intelligence_score": getattr(vulnerability, "threat_intelligence_score", None),
            "exploitability_prediction": exploitability_probability,
            "exploit_candidate": {
                "source": getattr(exploit, "source", None),
                "module_name": getattr(exploit, "module_name", None),
                "title": getattr(exploit, "title", None),
                "reliability_score": getattr(exploit, "reliability_score", None),
            } if exploit is not None else None,
        }

    @staticmethod
    def _exploit_technical_execution(exploit, exploit_evidence: dict[str, Any]) -> dict[str, Any]:
        return {
            "metasploit_module": f"{exploit_evidence.get('module_type')}/{exploit_evidence.get('module_name')}"
            if exploit_evidence.get("module_name") else getattr(exploit, "module_name", None),
            "target": exploit_evidence.get("target"),
            "execution_outcome": exploit_evidence.get("execution_outcome"),
            "session_id": exploit_evidence.get("session_id"),
            "session_type": exploit_evidence.get("session_type"),
            "exit_code": exploit_evidence.get("exit_code"),
            "stdout_excerpt": (exploit_evidence.get("stdout") or "")[-2000:] or None,
            "stderr": exploit_evidence.get("stderr") or None,
        }

    @staticmethod
    def _evidence_collected(exploit_evidence: dict[str, Any]) -> dict[str, Any]:
        return {
            "markers": exploit_evidence.get("markers", []),
            "shell_established": exploit_evidence.get("session_id") is not None,
            "user": exploit_evidence.get("user"),
            "hostname": exploit_evidence.get("hostname"),
            "operating_system": exploit_evidence.get("operating_system"),
            "architecture": exploit_evidence.get("architecture"),
            "working_directory": exploit_evidence.get("working_directory"),
            "detected_version": exploit_evidence.get("detected_version"),
            "callback_received": "callback_received" in (exploit_evidence.get("markers") or []),
        }

    @staticmethod
    def _validation_engine_section(initial_validation) -> dict[str, Any]:
        return {
            "status": getattr(initial_validation, "status", None),
            "validation_score": getattr(initial_validation, "validation_score", None),
            "analysis": getattr(initial_validation, "analysis", None),
            "scoring_methodology": VALIDATION_SCORE_EXPLANATION,
        }

    def _recommendation_section(self, recommendation, current_twin, new_twin, approval) -> dict[str, Any]:
        fixed_version = (getattr(approval, "context", None) or {}).get("fixed_version") if approval else None
        current_version = None
        if current_twin is not None:
            from services.common.version_utils import detect_version_from_image_tag
            current_version = detect_version_from_image_tag(getattr(current_twin, "twin_image", None))

        return {
            "recommendation_id": getattr(recommendation, "id", None),
            "title": getattr(recommendation, "title", None),
            "reasoning": getattr(recommendation, "content", None),
            "source": getattr(recommendation, "provider", None),
            "current_version": current_version,
            "fixed_version": fixed_version or (getattr(new_twin, "twin_image", None)),
            "limitations": (
                [] if recommendation is not None
                else ["This remediation has no backing recommendation record."]
            ),
        }

    @staticmethod
    def _human_approval_section(approval) -> dict[str, Any]:
        if approval is None:
            return {"note": "No approval record is linked to this remediation."}
        return {
            "approval_id": getattr(approval, "id", None),
            "reviewer": getattr(approval, "decided_by", None),
            "requested_by": getattr(approval, "requested_by", None),
            "decision": getattr(approval, "status", None),
            "decision_reason": getattr(approval, "decision_reason", None),
            "requested_at": getattr(approval, "created_at", None),
            "decided_at": getattr(approval, "decided_at", None),
            "reviewed_sections": [
                "vulnerability", "recommendation", "target_twin",
                "current_version", "fixed_version", "limitations",
            ],
        }

    def _remediation_execution_section(self, remediation, old_twin, new_twin) -> dict[str, Any]:
        evidence = getattr(remediation, "evidence", None) or {}
        return {
            "remediation_id": getattr(remediation, "id", None),
            "target_twin_id": getattr(remediation, "target_twin_id", None),
            "executor": getattr(remediation, "executor", None),
            "handler": getattr(remediation, "handler", None),
            "execution_authorized": getattr(remediation, "execution_authorized", None),
            "target_modified": getattr(remediation, "target_modified", None),
            "old_environment": self._twin_snapshot(old_twin),
            "new_environment": self._twin_snapshot(new_twin),
            "execution_started_at": getattr(remediation, "execution_started_at", None),
            "execution_completed_at": getattr(remediation, "execution_completed_at", None),
            "raw_evidence": evidence,
        }

    @staticmethod
    def _revalidation_section(exploit, new_twin, revalidation, revalidation_evidence, revalidation_comparison) -> dict[str, Any]:
        if revalidation is None:
            return {"note": "No revalidation has been run for this remediation yet."}
        return {
            "same_exploit_module": getattr(exploit, "module_name", None),
            "target_twin_id": getattr(new_twin, "id", None),
            "target_version": revalidation_evidence.get("detected_version"),
            "result_status": getattr(revalidation, "status", None),
            "validation_score": getattr(revalidation, "validation_score", None),
            "execution_outcome": revalidation_evidence.get("execution_outcome"),
            "comparison_summary": revalidation_comparison,
            "evidence": revalidation_evidence,
        }

    @staticmethod
    def _final_security_state(remediation, before_after) -> dict[str, Any]:
        resolved = (before_after or {}).get("resolved")
        return {
            "status": getattr(remediation, "status", None),
            "resolved": resolved,
            "verified_at": getattr(remediation, "verified_at", None),
            "statement": (
                "The vulnerability was demonstrated to no longer be exploitable against the "
                "remediated Digital Twin via an independent, real re-execution of the same exploit."
                if resolved is True else
                "The vulnerability remains exploitable, was not conclusively resolved, or has not "
                "yet been revalidated -- see sections 10 and 11 for detail."
            ),
        }

    @staticmethod
    def _limitations(approval, cve_explanation, mock_mode: bool) -> list[str]:
        limitations: list[str] = []

        if mock_mode:
            limitations.append(
                "Part or all of this run executed in MOCK_MODE: exploit execution and/or Digital "
                "Twin provisioning were simulated, not performed against real infrastructure. "
                "Any evidence tagged simulated=true in this report did not come from a real "
                "Metasploit session or a real Docker container."
            )

        if not cve_explanation.get("available"):
            limitations.append(cve_explanation.get("note", "No curated technical explanation available for this CVE."))

        review_package = (getattr(approval, "context", None) or {}).get("review_package") if approval else None
        if review_package:
            limitations.extend(review_package.get("limitations", []))

        limitations.append(
            "This report reflects AutoSecTwin's own recorded evidence only; it is not a substitute "
            "for independent verification against production systems, which this tool never touches."
        )

        return limitations

    @staticmethod
    def _technical_appendix(vulnerability, exploit, initial_validation, recommendation, approval, remediation, revalidation, old_twin, new_twin, audit_trail) -> dict[str, Any]:
        return {
            "database_ids": {
                "vulnerability_id": getattr(vulnerability, "id", None),
                "exploit_id": getattr(exploit, "id", None),
                "initial_validation_id": getattr(initial_validation, "id", None),
                "recommendation_id": getattr(recommendation, "id", None),
                "approval_id": getattr(approval, "id", None),
                "remediation_id": getattr(remediation, "id", None),
                "revalidation_id": getattr(revalidation, "id", None),
                "old_twin_id": getattr(old_twin, "id", None),
                "new_twin_id": getattr(new_twin, "id", None),
            },
            "exploit_module": getattr(exploit, "module_name", None),
            "api_endpoints_involved": [
                "POST /orchestration/run",
                "POST /approvals/",
                "PATCH /approvals/{id}/decision",
                "POST /remediations/{id}/execute",
                "POST /remediations/{id}/revalidate",
                "GET /reports/{id}/html",
                "GET /reports/{id}/pdf",
            ],
            "audit_trail": audit_trail,
        }

    # -- rendering ------------------------------------------------------

    def render_pdf(self, content_json: str, title: str | None = None) -> bytes:
        """Render a persisted JSON report body as a PDF document."""

        from reportlab.lib import colors

        try:
            body = json.loads(content_json)
        except (TypeError, ValueError):
            body = {"raw": content_json}

        report_title = title or body.get("title") or "AutoSecTwin Report"

        styles = getSampleStyleSheet()
        heading_style = ParagraphStyle(
            "AutoSecTwinHeading", parent=styles["Heading2"], spaceBefore=14, spaceAfter=6
        )
        body_style = styles["BodyText"]

        story: list[Any] = [Paragraph(self._escape(report_title), styles["Title"]), Spacer(1, 0.25 * inch)]

        for key, value in body.items():
            if key in {"title", "report_type", "generated_in_mock_mode"}:
                continue
            story.append(Paragraph(self._escape(self._section_label(key)), heading_style))
            story.extend(self._pdf_render_value(value, body_style, colors))

        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter, title=report_title)
        doc.build(story)
        return buffer.getvalue()

    def _pdf_render_value(self, value: Any, body_style, colors) -> list[Any]:
        """Recursively convert a JSON value into reportlab flowables."""

        if isinstance(value, dict):
            if not value:
                return [Paragraph("n/a", body_style)]
            rows = [
                [Paragraph(f"<b>{self._escape(str(k))}</b>", body_style), Paragraph(self._pdf_scalar(v), body_style)]
                for k, v in value.items()
            ]
            table = Table(rows, colWidths=[150, 330])
            table.setStyle(
                TableStyle(
                    [
                        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                        ("BACKGROUND", (0, 0), (0, -1), colors.whitesmoke),
                        ("VALIGN", (0, 0), (-1, -1), "TOP"),
                        ("FONTSIZE", (0, 0), (-1, -1), 9),
                    ]
                )
            )
            return [table, Spacer(1, 0.15 * inch)]

        if isinstance(value, list):
            if not value:
                return [Paragraph("None", body_style)]
            items = [ListItem(Paragraph(self._pdf_scalar(item), body_style)) for item in value]
            return [ListFlowable(items, bulletType="bullet"), Spacer(1, 0.15 * inch)]

        return [Paragraph(self._pdf_scalar(value), body_style), Spacer(1, 0.1 * inch)]

    def _pdf_scalar(self, value: Any) -> str:
        if isinstance(value, (dict, list)):
            return self._escape(json.dumps(value, default=str))
        if value is None:
            return "n/a"
        return self._escape(str(value))

    def render_html(self, content_json: str, title: str | None = None) -> str:
        """Render a persisted JSON report body as a human-readable HTML page."""

        try:
            body = json.loads(content_json)
        except (TypeError, ValueError):
            body = {"raw": content_json}

        report_title = title or body.get("title") or "AutoSecTwin Report"

        sections_html = "".join(
            self._render_section(key, value)
            for key, value in body.items()
            if key not in {"title", "report_type", "generated_in_mock_mode"}
        )

        mock_banner = (
            '<div class="mock-banner">Generated with MOCK_MODE active -- some evidence in this '
            "report is simulated, not from real infrastructure.</div>"
            if body.get("generated_in_mock_mode") else ""
        )

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{self._escape(report_title)}</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, Roboto, sans-serif; margin: 2rem; color: #1a1a1a; background: #fafafa; max-width: 960px; margin-left:auto; margin-right:auto;}}
  h1 {{ border-bottom: 2px solid #333; padding-bottom: 0.5rem; }}
  h2 {{ margin-top: 2.5rem; color: #1a1a1a; border-left: 4px solid #555; padding-left: 0.6rem; }}
  table {{ border-collapse: collapse; width: 100%; margin: 0.5rem 0 1.5rem; background: #fff; }}
  th, td {{ text-align: left; padding: 0.4rem 0.75rem; border: 1px solid #ddd; vertical-align: top; }}
  th {{ background: #f0f0f0; width: 260px; }}
  .badge {{ display: inline-block; padding: 0.15rem 0.6rem; border-radius: 999px; background: #e0e0e0; font-size: 0.85rem; }}
  pre {{ background: #f5f5f5; padding: 0.75rem; overflow-x: auto; border-radius: 4px; white-space: pre-wrap; }}
  .mock-banner {{ background: #fff3cd; border: 1px solid #ffe69c; padding: 0.75rem 1rem; border-radius: 4px; margin-bottom: 1.5rem; }}
  .flow {{ display:flex; flex-wrap:wrap; align-items:center; gap:0.4rem; margin: 1rem 0; }}
  .flow .step {{ background:#eef2f7; border:1px solid #c9d4e3; border-radius:6px; padding:0.5rem 0.8rem; font-size:0.9rem; }}
  .flow .arrow {{ color:#888; }}
  .before-after {{ display:flex; gap:1rem; }}
  .before-after > div {{ flex:1; }}
  .resolved-yes {{ color:#0a7a33; font-weight:600; }}
  .resolved-no {{ color:#a4262c; font-weight:600; }}
</style>
</head>
<body>
<h1>{self._escape(report_title)}</h1>
{mock_banner}
{sections_html}
</body>
</html>"""

    def _render_section(self, key: str, value: Any) -> str:
        heading = f"<h2>{self._escape(self._section_label(key))}</h2>"

        if key == "3_vulnerability_technical_analysis" and isinstance(value, dict) and value.get("attack_chain"):
            return heading + self._render_attack_chain(value)

        if key == "12_before_vs_after" and isinstance(value, dict) and "before" in value and "after" in value:
            return heading + self._render_before_after(value)

        if key == "15_technical_appendix" and isinstance(value, dict) and "audit_trail" in value:
            return heading + self._render_appendix(value)

        if isinstance(value, dict):
            rows = "".join(
                f"<tr><th>{self._escape(str(k))}</th><td>{self._render_value(v)}</td></tr>"
                for k, v in value.items()
            )
            return f"{heading}<table>{rows}</table>"

        if isinstance(value, list):
            items = "".join(f"<li>{self._render_value(item)}</li>" for item in value)
            return f"{heading}<ul>{items}</ul>"

        return f"{heading}<p>{self._render_value(value)}</p>"

    def _render_attack_chain(self, value: dict[str, Any]) -> str:
        other_rows = "".join(
            f"<tr><th>{self._escape(str(k).replace('_', ' ').title())}</th><td>{self._render_value(v)}</td></tr>"
            for k, v in value.items()
            if k != "attack_chain"
        )
        steps = value.get("attack_chain") or []
        flow = "".join(
            f'<div class="step">{i + 1}. {self._escape(step)}</div>'
            + ('<span class="arrow">&#8594;</span>' if i < len(steps) - 1 else "")
            for i, step in enumerate(steps)
        )
        return f"<table>{other_rows}</table><div class=\"flow\">{flow}</div>"

    def _render_before_after(self, value: dict[str, Any]) -> str:
        before, after = value.get("before", {}), value.get("after", {})
        resolved = value.get("resolved")
        resolved_html = (
            f'<p class="resolved-{"yes" if resolved else "no"}">Resolved: {resolved}</p>'
        )

        def _col(label: str, data: dict[str, Any]) -> str:
            rows = "".join(
                f"<tr><th>{self._escape(str(k))}</th><td>{self._render_value(v)}</td></tr>"
                for k, v in data.items()
            )
            return f"<div><h3>{self._escape(label)}</h3><table>{rows}</table></div>"

        return f'<div class="before-after">{_col("Before", before)}{_col("After", after)}</div>{resolved_html}'

    def _render_appendix(self, value: dict[str, Any]) -> str:
        parts = []
        for k, v in value.items():
            if k == "audit_trail" and isinstance(v, list):
                rows = "".join(
                    f"<tr><td>{self._escape(str(e.get('timestamp')))}</td>"
                    f"<td>{self._escape(str(e.get('event')))}</td>"
                    f"<td>{self._escape(str(e.get('detail') or ''))}</td></tr>"
                    for e in v
                )
                parts.append(
                    f"<h3>Execution Timeline</h3><table><tr><th>Timestamp</th><th>Event</th><th>Detail</th></tr>{rows}</table>"
                )
            else:
                parts.append(f"<h3>{self._escape(str(k).replace('_', ' ').title())}</h3>{self._render_value(v)}")
        return "".join(parts)

    @staticmethod
    def _section_label(key: str) -> str:
        # Strip a leading "N_" ordering prefix for display, e.g.
        # "3_vulnerability_technical_analysis" -> "Vulnerability Technical Analysis"
        parts = key.split("_", 1)
        label = parts[1] if len(parts) == 2 and parts[0].isdigit() else key
        return label.replace("_", " ").title()

    def _render_value(self, value: Any) -> str:
        if isinstance(value, dict) or isinstance(value, list):
            return f"<pre>{self._escape(json.dumps(value, indent=2, default=str))}</pre>"
        if value is None:
            return "<span class=\"badge\">n/a</span>"
        return self._escape(str(value))

    @staticmethod
    def _escape(text: str) -> str:
        return (
            text.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
        )

    @staticmethod
    def _summary(report_type: str, payload: dict[str, Any]) -> str:
        if report_type == "executive":
            return "Business risk, confidence, and remediation status summary."
        if report_type == "trust":
            return "AI prediction trust, hallucination, and drift summary."
        if report_type == "legacy":
            return "Unsupported software and compensating controls summary."
        if report_type == "remediation":
            return "Recommended and applied remediation actions summary."
        if report_type == "validation":
            return "Digital twin validation evidence summary."
        if report_type == "closed_loop":
            return "Full detect-to-remediate-to-revalidate closed loop summary."
        return "Technical vulnerability and exploitation detail summary."
