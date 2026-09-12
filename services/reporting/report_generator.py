import io
import json
from typing import Any

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
        """Generate a JSON report body for the requested report type.

        Args:
            report_type: One of the supported AutoSecTwin report categories.
            title: Report title.
            payload: Normalized reporting data.

        Returns:
            JSON report content suitable for persistence or PDF rendering.
        """

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
    ) -> str:
        """Build a full closed-loop report from persisted lifecycle data.

        Every section is populated from database rows passed in by the
        caller (the closed-loop orchestrator), never from ad hoc runtime
        variables, so the report always reflects what actually happened.
        """

        body = {
            "report_type": "closed_loop",
            "title": title,
            "generated_in_mock_mode": mock_mode,
            "executive_summary": {
                "asset": getattr(getattr(vulnerability, "asset", None), "name", None),
                "vulnerability": getattr(vulnerability, "cve_id", None),
                "risk_severity": getattr(vulnerability, "severity", None),
                "exploitability_probability": exploitability_probability,
                "validation_result": getattr(initial_validation, "status", None),
                "remediation_result": getattr(remediation, "status", None),
                "final_status": final_status,
            },
            "vulnerability": {
                "cve_id": getattr(vulnerability, "cve_id", None),
                "cvss_score": getattr(vulnerability, "cvss_score", None),
                "epss_score": getattr(vulnerability, "epss_score", None),
                "kev_listed": getattr(vulnerability, "kev_listed", None),
                "description": getattr(vulnerability, "description", None),
            },
            "digital_twin": {
                "twin_id": getattr(twin, "id", None),
                "environment": getattr(twin, "environment", None),
                "ip_address": getattr(twin, "ip_address", None),
                "twin_image": getattr(twin, "twin_image", None),
                "health": getattr(twin, "health", None),
                "status": getattr(twin, "status", None),
            } if twin is not None else None,
            "exploit_validation": {
                "exploit_module": getattr(exploit, "module_name", None) if exploit else None,
                "status": getattr(initial_validation, "status", None) if initial_validation else None,
                "validation_score": getattr(initial_validation, "validation_score", None) if initial_validation else None,
                "analysis": getattr(initial_validation, "analysis", None) if initial_validation else None,
                "evidence": getattr(initial_validation, "evidence", None) if initial_validation else None,
            },
            "remediation": {
                "action": getattr(remediation, "action", None) if remediation else None,
                "status": getattr(remediation, "status", None) if remediation else None,
                "applied_at": getattr(remediation, "applied_at", None) if remediation else None,
                "verification_score": getattr(remediation, "verification_score", None) if remediation else None,
            },
            "revalidation": {
                "status": getattr(revalidation, "status", None) if revalidation else None,
                "validation_score": getattr(revalidation, "validation_score", None) if revalidation else None,
                "comparison": revalidation_comparison,
            },
            "audit_trail": audit_trail,
        }
        return json.dumps(body, indent=2, default=str)

    def render_pdf(self, content_json: str, title: str | None = None) -> bytes:
        """Render a persisted JSON report body as a PDF document.

        Uses reportlab (pure Python, no system libraries required) so this
        works in constrained deployment environments that can't install
        weasyprint/wkhtmltopdf's native dependencies. Walks the same JSON
        structure ``render_html`` does, so both are always in sync.
        """

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
            if key in {"title", "report_type"}:
                continue
            story.append(Paragraph(self._escape(key.replace("_", " ").title()), heading_style))
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
        """Render a persisted JSON report body as a human-readable HTML page.

        Accepts the output of either ``generate()`` or
        ``generate_closed_loop_report()`` -- both are plain JSON, so this
        never needs to know which one produced a given report.
        """

        try:
            body = json.loads(content_json)
        except (TypeError, ValueError):
            body = {"raw": content_json}

        report_title = title or body.get("title") or "AutoSecTwin Report"

        sections_html = "".join(
            self._render_section(key, value)
            for key, value in body.items()
            if key not in {"title", "report_type"}
        )

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{self._escape(report_title)}</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, Roboto, sans-serif; margin: 2rem; color: #1a1a1a; background: #fafafa; }}
  h1 {{ border-bottom: 2px solid #333; padding-bottom: 0.5rem; }}
  h2 {{ margin-top: 2rem; color: #333; text-transform: capitalize; }}
  table {{ border-collapse: collapse; width: 100%; margin: 0.5rem 0 1.5rem; background: #fff; }}
  th, td {{ text-align: left; padding: 0.4rem 0.75rem; border: 1px solid #ddd; vertical-align: top; }}
  th {{ background: #f0f0f0; width: 220px; }}
  .badge {{ display: inline-block; padding: 0.15rem 0.6rem; border-radius: 999px; background: #e0e0e0; font-size: 0.85rem; }}
  pre {{ background: #f5f5f5; padding: 0.75rem; overflow-x: auto; border-radius: 4px; }}
</style>
</head>
<body>
<h1>{self._escape(report_title)}</h1>
{sections_html}
</body>
</html>"""

    def _render_section(self, key: str, value: Any) -> str:
        heading = f"<h2>{self._escape(key.replace('_', ' '))}</h2>"

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
