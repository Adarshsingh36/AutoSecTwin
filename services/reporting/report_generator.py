import json
from typing import Any


class ReportGenerator:
    """Generates executive, technical, trust, legacy, remediation, and validation reports."""

    SUPPORTED_TYPES = {
        "executive",
        "technical",
        "trust",
        "legacy",
        "remediation",
        "validation",
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
        return "Technical vulnerability and exploitation detail summary."
